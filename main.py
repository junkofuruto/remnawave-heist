#!/usr/bin/env python3

import copy
import json, logging, math, os, re, secrets, sys, urllib.parse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone

from downloads import download_opener
from environment import config
from geoip import GeoIP, GeoIPError
from logging_setup import configure_logging
from remnawave_api import ProfileConflictError, RemnawaveAPI
from state import StateError, load_state, outbound_hash, save_state, state_lock, subscription_hash
from vless import fetch_subscription, link_to_outbound
from xray_probe import XrayProbeError, check_outbound, check_speed, require_xray

logger = logging.getLogger("remnawave.main")

TAG_PREFIX = "out-auto-"
DRY_RUN = "--dry-run" in sys.argv

def probe_with_retries(outbound):
    for attempt in range(1, config.probe_attempts + 1):
        result = check_outbound(outbound, config.probe_urls, config.probe_timeout, config.xray_binary)
        if result and (not isinstance(result.latency_ms, (int, float))
                       or not math.isfinite(result.latency_ms) or result.latency_ms < 0):
            logger.warning("Outbound %s returned an invalid latency", outbound["tag"])
            result = None
        if result:
            if attempt > 1:
                logger.info("Outbound %s recovered on attempt %d/%d", outbound["tag"], attempt, config.probe_attempts)
            return result
        if attempt < config.probe_attempts:
            logger.warning("Retrying outbound %s (%d/%d)", outbound["tag"], attempt + 1, config.probe_attempts)
    return None


def probe_candidates(candidates, geoip):
    """Return passing candidates, checking a bounded number concurrently."""
    pending, results = {}, []
    with ThreadPoolExecutor(max_workers=config.probe_concurrency) as pool:
        try:
            for order, (outbound, sources) in enumerate(candidates):
                address = outbound["settings"]["vnext"][0]["address"]
                if geoip is not None and not geoip.is_european(address):
                    continue
                future = pool.submit(probe_with_retries, outbound)
                pending[future] = (outbound, sources, order)
                if len(pending) >= config.probe_concurrency:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        item, source_ids, position = pending.pop(future)
                        result = future.result()
                        if result:
                            results.append((item, source_ids, result, position))
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    item, source_ids, position = pending.pop(future)
                    result = future.result()
                    if result:
                        results.append((item, source_ids, result, position))
        finally:
            for future in pending:
                future.cancel()
    results.sort(key=lambda item: (item[2].latency_ms, item[3]))
    return [(outbound, sources, result) for outbound, sources, result, _ in results]


def refresh_subscriptions(opener):
    """Fetch every source before accepting removals; deduplicate by config hash."""
    discovered = {}
    incomplete_sources = set()
    for index, url in enumerate(config.urls, 1):
        logger.info("Reading subscription %d/%d", index, len(config.urls))
        try:
            links = fetch_subscription(url, opener)
        except (OSError, ValueError):
            logger.error("Failed to read subscription %d; keeping saved state", index)
            raise SystemExit(1) from None
        if not links:
            logger.error("Subscription %d has no VLESS links; keeping saved state", index)
            raise SystemExit(1)
        source = subscription_hash(url)
        valid_count = 0
        invalid_count = 0
        for link in links:
            try:
                name = urllib.parse.unquote(urllib.parse.urlsplit(link).fragment) or "node"
                slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")[:20] or "node"
                outbound = link_to_outbound(link, "")
                vnext = outbound["settings"]["vnext"][0]
                if not vnext["address"] or not vnext["users"][0]["id"]:
                    raise ValueError("missing server or user")
                digest = outbound_hash(outbound)
                outbound["tag"] = f"{TAG_PREFIX}{digest[:16]}-{slug}"
            except (ValueError, TypeError, KeyError, IndexError, UnicodeError):
                invalid_count += 1
                continue
            valid_count += 1
            if digest in discovered:
                if source not in discovered[digest][1]:
                    discovered[digest][1].append(source)
            else:
                discovered[digest] = (outbound, [source])
        if not valid_count:
            logger.error("Subscription %d has no valid VLESS configurations; keeping saved state", index)
            raise SystemExit(1)
        if invalid_count:
            incomplete_sources.add(source)
            logger.warning("Skipped %d invalid VLESS configuration(s) in subscription %d; preserving previous entries until a clean refresh",
                           invalid_count, index)
    return discovered, incomplete_sources


def rank_saved(state):
    items = [item for item in state["outbounds"].values() if item.get("latency_ms") is not None]
    return sorted(items, key=lambda item: (-(item.get("download_mbps") or 0), item["latency_ms"],
                                           outbound_hash(item["outbound"])))


def save_checked_state(state):
    if DRY_RUN:
        return
    try:
        save_state(config.state_file, state)
    except StateError as e:
        logger.error("%s; profile not updated", e)
        raise SystemExit(1) from None


def _routing_tag_references(value):
    """Collect explicit outbound-tag references from a profile's routing rules."""
    if isinstance(value, dict):
        references = set()
        for key, child in value.items():
            if key in ("outboundTag", "fallbackTag") and isinstance(child, str):
                references.add(child)
            else:
                references.update(_routing_tag_references(child))
        return references
    if isinstance(value, list):
        return set().union(*(_routing_tag_references(item) for item in value)) if value else set()
    return set()


def publish_saved(state, api, profile, run_id, retired_active=None):
    original = profile.get("config", profile)
    if isinstance(original, str):
        original = json.loads(original)
    ranked = rank_saved(state)
    # Keep the panel's existing tag for active configurations: routing rules may
    # reference it. For duplicate hashes, preserve the first panel occurrence.
    panel_managed = {}
    for outbound in original.get("outbounds", []):
        if str(outbound.get("tag", "")).startswith(TAG_PREFIX):
            panel_managed.setdefault(outbound_hash(outbound), outbound)
    for item in ranked:
        digest = outbound_hash(item["outbound"])
        if item.get("active") and digest in panel_managed:
            item["outbound"] = copy.deepcopy(panel_managed[digest])
    # Keep healthy active entries stable; fill vacancies from the best reserve.
    active = [item for item in ranked if item.get("active")][:config.max_outbounds]
    active_hashes = {outbound_hash(item["outbound"]) for item in active}
    reserve = [item for item in ranked if outbound_hash(item["outbound"]) not in active_hashes]
    selected = active + reserve[:config.max_outbounds - len(active)]
    panel_references = _routing_tag_references(original.get("routing", {}))
    duplicate_tags = {}
    for outbound in original.get("outbounds", []):
        tag = outbound.get("tag")
        if isinstance(tag, str) and tag.startswith(TAG_PREFIX):
            duplicate_tags.setdefault(outbound_hash(outbound), []).append(outbound)
    for item in selected:
        matches = duplicate_tags.get(outbound_hash(item["outbound"]), [])
        referenced = [candidate for candidate in matches if candidate.get("tag") in panel_references]
        if referenced:
            item["outbound"] = copy.deepcopy(referenced[0])
    if not selected:
        logger.error("No healthy replacement available; profile not changed")
        raise SystemExit(1)
    existing = original.get("outbounds", [])
    missing_fixed = {"direct", "block"} - {item.get("tag") for item in existing}
    if missing_fixed:
        logger.warning("Profile has no outbound(s): %s", ", ".join(sorted(missing_fixed)))
    base = [outbound for outbound in existing if not str(outbound.get("tag", "")).startswith(TAG_PREFIX)]
    proposed = base + [item["outbound"] for item in selected]
    removed_tags = {item.get("tag") for item in existing if isinstance(item.get("tag"), str)} - {
        item.get("tag") for item in proposed if isinstance(item.get("tag"), str)
    }
    referenced = removed_tags & panel_references
    if referenced:
        logger.error("Cannot remove %d managed outbound(s) referenced by routing rules; profile not changed", len(referenced))
        raise SystemExit(1)
    previous_managed = [item for item in existing if str(item.get("tag", "")).startswith(TAG_PREFIX)]
    proposed_managed = [item for item in proposed if str(item.get("tag", "")).startswith(TAG_PREFIX)]
    old_by_tag = {}
    for item in previous_managed:
        old_by_tag.setdefault(item.get("tag"), set()).add(outbound_hash(item))
    stable_tag_change = any(item.get("tag") in old_by_tag
                            and outbound_hash(item) not in old_by_tag[item.get("tag")]
                            for item in proposed_managed)
    if stable_tag_change:
        logger.error("A managed tag would be reused for a different configuration; profile not changed")
        raise SystemExit(1)
    if proposed == existing:
        if not DRY_RUN:
            selected_hashes = {outbound_hash(item["outbound"]) for item in selected}
            for digest, item in state["outbounds"].items():
                item["active"] = digest in selected_hashes
            save_checked_state(state)
        return selected, existing
    if DRY_RUN:
        logger.info("Dry run: would publish %d healthy outbounds", len(selected))
        return selected, existing
    try:
        os.makedirs(config.backup_dir, exist_ok=True)
        backup = os.path.join(config.backup_dir, f"{config.profile}-{datetime.now():%Y%m%d-%H%M%S}-{run_id}.json")
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(profile, output, indent=2)
    except OSError:
        logger.error("Could not save profile backup; profile not changed")
        raise SystemExit(1) from None
    state["pending"] = {"previous": copy.deepcopy(existing), "proposed": copy.deepcopy(proposed),
                        "previous_records": copy.deepcopy(retired_active or {})}
    save_checked_state(state)
    try:
        api.update_outbounds(config.profile, existing, proposed)
    except ProfileConflictError:
        state.pop("pending", None)
        save_checked_state(state)
        logger.error("Panel outbounds changed externally; stopping without overwriting; backup: %s", backup)
        raise SystemExit(1) from None
    except SystemExit:
        logger.error("Panel update outcome is uncertain; rerun to reconcile state; backup: %s", backup)
        raise
    selected_hashes = {outbound_hash(item["outbound"]) for item in selected}
    for digest, item in state["outbounds"].items():
        item["active"] = digest in selected_hashes
    state.pop("pending", None)
    save_checked_state(state)
    logger.info("Published %d healthy outbounds; backup: %s", len(selected), backup)
    if retired_active:
        logger.info("Removed %d active configuration(s) absent from refreshed subscriptions", len(retired_active))
    return selected, proposed


def update_pool(state, passing):
    now = datetime.now(timezone.utc).isoformat()
    for outbound, sources, latency in passing:
        digest = outbound_hash(outbound)
        previous = state["outbounds"].get(digest, {})
        state["outbounds"][digest] = {
            "outbound": outbound,
            "sources": list(sources),
            "latency_ms": latency.latency_ms,
            "last_latency_ms": latency.latency_ms,
            "download_mbps": previous.get("download_mbps"),
            "checked_at": now,
            "active": previous.get("active", False),
        }


def refresh_speed(state, digests):
    # Speed tests are optional for retention; connectivity determines health.
    pending = {}
    with ThreadPoolExecutor(max_workers=config.probe_concurrency) as pool:
        try:
            for digest in digests:
                item = state["outbounds"].get(digest)
                if item is None:
                    continue
                future = pool.submit(check_speed, item["outbound"], config.speed_test_url,
                                     config.speed_test_bytes, config.probe_timeout, config.xray_binary)
                pending[future] = item
                if len(pending) >= config.probe_concurrency:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for completed in done:
                        target = pending.pop(completed)
                        speed = completed.result()
                        if (speed and isinstance(speed.download_mbps, (int, float))
                                and math.isfinite(speed.download_mbps) and speed.download_mbps > 0):
                            target["download_mbps"] = speed.download_mbps
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for completed in done:
                    target = pending.pop(completed)
                    speed = completed.result()
                    if (speed and isinstance(speed.download_mbps, (int, float))
                            and math.isfinite(speed.download_mbps) and speed.download_mbps > 0):
                        target["download_mbps"] = speed.download_mbps
        finally:
            for future in pending:
                future.cancel()


def log_results(state, selected_items):
    logger.info("Best healthy outbounds:")
    source_numbers = {subscription_hash(url): index for index, url in enumerate(config.urls, 1)}
    for index, item in enumerate(selected_items, 1):
        sources = ",".join(str(source_numbers[s]) for s in item["sources"] if s in source_numbers) or "unknown"
        speed = item.get("download_mbps")
        logger.info("#%d subscription %s | %s | latency %.1f ms | download %s", index, sources,
                    item["outbound"]["tag"], item["latency_ms"],
                    f"{speed:.2f} Mbps" if speed is not None else "not measured")


def run_routines():
    logger.info("Starting %s", "dry run" if DRY_RUN else "profile maintenance")
    try:
        require_xray(config.xray_binary)
        state = load_state(config.state_file, config.url, config.profile, restrict_permissions=not DRY_RUN)
        api = RemnawaveAPI(config.url, config.token, config.ssl_ctx)
        profile = api.get_profile(config.profile)
        panel_config = profile.get("config", profile)
        if isinstance(panel_config, str):
            panel_config = json.loads(panel_config)
        pending_update = state.get("pending")
        if pending_update:
            actual = panel_config.get("outbounds", [])
            if actual == pending_update["proposed"]:
                applied = True
            elif actual == pending_update["previous"]:
                applied = False
            else:
                raise StateError("panel differs from pending update; manual reconciliation required")
            if not applied:
                state["outbounds"].update(pending_update.get("previous_records", {}))
            logger.info("Reconciled an interrupted panel update against the current profile")
            state.pop("pending")
        managed = [item for item in panel_config.get("outbounds", [])
                   if str(item.get("tag", "")).startswith(TAG_PREFIX)]
        panel_hashes = {outbound_hash(item) for item in managed}
        duplicate_count = len(managed) - len(panel_hashes)
        if duplicate_count:
            logger.warning("Panel contains %d duplicate managed outbound(s); they will be reconciled after successful checks",
                           duplicate_count)
        saved = state["outbounds"]
        unknown_active = panel_hashes - set(saved)
        if saved and unknown_active:
            raise StateError("panel contains managed outbounds missing from persistent state; manual reconciliation required")
        # The panel is authoritative for which previously selected candidates
        # are currently in use; persisted timestamps are not proof of activity.
        for digest, item in saved.items():
            item["active"] = digest in panel_hashes

        opener = download_opener(config.proxy)
        geoip = None
        if config.location == "europe":
            logger.info("Loading GeoIP databases")
            geoip = GeoIP(config.geoip_ipv4_url, config.geoip_ipv6_url, config.geoip_cache_dir, opener)

        # Run health maintenance before contacting subscriptions.
        if saved:
            logger.info("Routine 1: rechecking %d saved outbounds", len(saved))
            known = [(item["outbound"], item["sources"]) for item in saved.values()]
            passing = probe_candidates(known, geoip)
            healthy_hashes = {outbound_hash(item[0]) for item in passing}
            for digest, item in saved.items():
                if digest not in healthy_hashes:
                    item["latency_ms"] = None
                    item["checked_at"] = datetime.now(timezone.utc).isoformat()
            update_pool(state, passing)
            save_checked_state(state)
        else:
            logger.info("Routine 1: no saved outbounds to recheck")

        if saved and rank_saved(state):
            first_selection, first_outbounds = publish_saved(state, api, profile, secrets.token_hex(4))
            first_hashes = {outbound_hash(item["outbound"]) for item in first_selection}
            for digest, item in saved.items():
                item["active"] = digest in first_hashes
            if not DRY_RUN:
                save_checked_state(state)
                profile = copy.deepcopy(profile)
                profile_config = profile.get("config", profile)
                if isinstance(profile_config, str):
                    profile_config = json.loads(profile_config)
                    profile["config"] = profile_config
                profile_config["outbounds"] = first_outbounds
            else:
                profile = copy.deepcopy(profile)
                profile_config = profile.get("config", profile)
                if isinstance(profile_config, str):
                    profile_config = json.loads(profile_config)
                    profile["config"] = profile_config
                profile_config["outbounds"] = [item for item in profile_config.get("outbounds", [])
                                               if not str(item.get("tag", "")).startswith(TAG_PREFIX)] + [
                                                   item["outbound"] for item in first_selection]
            panel_hashes = {outbound_hash(item) for item in profile_config["outbounds"]
                            if str(item.get("tag", "")).startswith(TAG_PREFIX)}
        elif saved:
            logger.warning("No saved outbounds passed; checking subscriptions for replacements")

        # Routine 2: only a complete successful refresh can remove entries.
        logger.info("Routine 2: checking subscriptions for updates")
        discovered, incomplete_sources = refresh_subscriptions(opener)
        retained_sources = {}
        for digest, item in saved.items():
            seen_sources = discovered[digest][1] if digest in discovered else []
            retained = [source for source in item["sources"] if source in incomplete_sources]
            sources = list(dict.fromkeys(seen_sources + retained))
            if sources:
                retained_sources[digest] = sources
        dropped_active = {digest: copy.deepcopy(item) for digest, item in saved.items()
                          if digest not in retained_sources and item.get("active")}
        for digest in list(saved):
            if digest not in retained_sources:
                del saved[digest]
            else:
                saved[digest]["sources"] = retained_sources[digest]
        new_candidates = [value for digest, value in discovered.items() if digest not in saved]
        logger.info("Found %d new configurations", len(new_candidates))
        passing_new = probe_candidates(new_candidates, geoip)
        update_pool(state, passing_new)
        for item in saved.values():
            if outbound_hash(item["outbound"]) in panel_hashes:
                item["active"] = True
        now = datetime.now(timezone.utc).isoformat()
        for outbound, sources in new_candidates:
            digest = outbound_hash(outbound)
            if digest not in saved:
                saved[digest] = {"outbound": outbound, "sources": list(sources), "latency_ms": None,
                                 "download_mbps": None, "checked_at": now, "active": False}
        if not rank_saved(state):
            saved.update(dropped_active)
            save_checked_state(state)
            logger.error("No healthy replacement available; profile not changed")
            raise SystemExit(1)
        try:
            selected_items, current_outbounds = publish_saved(state, api, profile, secrets.token_hex(4), dropped_active)
        except SystemExit:
            if not DRY_RUN and "pending" not in state:
                saved.update(dropped_active)
                save_checked_state(state)
            raise
        if not DRY_RUN:
            profile = copy.deepcopy(profile)
            profile_config = profile.get("config", profile)
            if isinstance(profile_config, str):
                profile_config = json.loads(profile_config)
                profile["config"] = profile_config
            profile_config["outbounds"] = current_outbounds
        accepted = {outbound_hash(item[0]) for item in passing_new}
        pending_measurements = [outbound_hash(item["outbound"]) for item in rank_saved(state)
                                if outbound_hash(item["outbound"]) in accepted]
        refresh_speed(state, pending_measurements)
        save_checked_state(state)
        selected_items, _ = publish_saved(state, api, profile, secrets.token_hex(4))
        log_results(state, selected_items)
        if DRY_RUN:
            logger.info("Dry run complete; profile and persistent state not updated")
            print(json.dumps([item["outbound"] for item in selected_items[:2]], indent=2))
    except (StateError, GeoIPError, XrayProbeError) as e:
        logger.error("%s; stopping without further panel updates", e)
        raise SystemExit(1) from None


def main():
    try:
        if DRY_RUN:
            run_routines()
        else:
            with state_lock(config.state_file):
                run_routines()
    except StateError as e:
        logger.error("%s; profile not changed", e)
        raise SystemExit(1) from None


if __name__ == "__main__":
    try:
        configure_logging(config.log_file)
    except OSError as e:
        sys.exit(f"cannot initialize log file: {e.strerror or 'filesystem error'}")
    main()

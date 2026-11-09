#!/usr/bin/env python3

import copy
import json, logging, math, os, re, secrets, sys, urllib.parse
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime

from downloads import download_opener
from environment import config
from geoip import GeoIP, GeoIPError
from logging_setup import configure_logging
from remnawave_api import ProfileConflictError, RemnawaveAPI
from vless import fetch_subscription, link_to_outbound
from xray_probe import XrayProbeError, check_outbound, check_speed, require_xray

logger = logging.getLogger("remnawave.main")

TAG_PREFIX = "out-auto-"
FIXED_TAGS = ("direct", "block")
DRY_RUN = "--dry-run" in sys.argv

def select_outbounds(opener, geoip, run_id):
    seen = set()
    results = []
    pending = deque()
    candidate_number = 0

    def collect_one():
        outbound, subscription, future = pending.popleft()
        try:
            measurement = future.result()
        except XrayProbeError as e:
            logger.error("Outbound %s: %s; profile not changed", outbound["tag"], e)
            raise SystemExit(1) from None
        if measurement:
            results.append((outbound, subscription, measurement))

    def drain_pending():
        while pending:
            collect_one()

    with ThreadPoolExecutor(max_workers=config.probe_concurrency) as pool:
        try:
            for index, url in enumerate(config.urls, 1):
                logger.info("Reading subscription %d/%d", index, len(config.urls))
                try:
                    links = fetch_subscription(url, opener)
                except (OSError, ValueError):
                    logger.error("Failed to read subscription %d", index)
                    raise SystemExit(1) from None
                for link in links:
                    if link in seen:
                        continue
                    seen.add(link)
                    try:
                        name = urllib.parse.unquote(urllib.parse.urlsplit(link).fragment) or "node"
                        slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")[:20] or "node"
                        tag = f"{TAG_PREFIX}{run_id}-{candidate_number + 1:02d}-{slug}"
                        outbound = link_to_outbound(link, tag)
                    except Exception:
                        logger.warning("Skipping invalid VLESS link")
                        continue
                    address = outbound["settings"]["vnext"][0]["address"]
                    if geoip is not None and not geoip.is_european(address):
                        continue
                    candidate_number += 1
                    future = pool.submit(check_outbound, outbound, config.probe_urls,
                                         config.probe_timeout, config.xray_binary)
                    pending.append((outbound, index, future))
                    if len(pending) >= config.probe_concurrency:
                        collect_one()
            drain_pending()
            results.sort(key=lambda item: item[2].latency_ms)
            return results
        finally:
            for _, _, future in pending:
                future.cancel()


def refine_outbounds(candidates, publish):
    """Publish latency winners, then progressively replace them with speed winners."""
    limit = config.max_outbounds
    initial, remaining = candidates[:limit], candidates[limit:]
    measured = []
    published_tags = tuple(item[0]["tag"] for item in initial)
    publish(initial, "temporary latency-ranked selection")

    def apply_best():
        nonlocal published_tags
        best = sorted(measured, key=lambda item: (-item[3].download_mbps, item[2].latency_ms, item[0]["tag"]))[:limit]
        tags = tuple(item[0]["tag"] for item in best)
        if tags and set(tags) != set(published_tags):
            publish(best, "speed-ranked selection")
            published_tags = tags
        return best

    def measure_group(group, incremental):
        # At most probe_concurrency processes; schedule in latency order and
        # handle results as they complete so improvements are published promptly.
        iterator = iter(group)
        with ThreadPoolExecutor(max_workers=config.probe_concurrency) as pool:
            pending = {}
            def submit_next():
                candidate = next(iterator, None)
                if candidate is None:
                    return False
                future = pool.submit(check_speed, candidate[0], config.speed_test_url,
                                     config.speed_test_bytes, config.probe_timeout, config.xray_binary)
                pending[future] = candidate
                return True
            for _ in range(min(config.probe_concurrency, len(group))):
                submit_next()
            try:
                while pending:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        candidate = pending.pop(future)
                        try:
                            speed = future.result()
                        except XrayProbeError as e:
                            logger.error("Outbound %s: %s; last confirmed profile retained", candidate[0]["tag"], e)
                            raise SystemExit(1) from None
                        if speed and math.isfinite(speed.download_mbps) and speed.download_mbps > 0:
                            measured.append((*candidate, speed))
                            if incremental:
                                apply_best()
                        submit_next()
            finally:
                for future in pending:
                    future.cancel()

    logger.info("Speed-testing %d initially selected outbounds first", len(initial))
    measure_group(initial, incremental=False)
    apply_best()
    logger.info("Speed-testing %d remaining probe-passing outbounds", len(remaining))
    measure_group(remaining, incremental=True)
    best = apply_best()
    if not best:
        logger.error("No outbound passed the speed check; temporary latency-ranked selection remains")
        raise SystemExit(1)
    return best


def main():
    logger.info("Starting %s", "dry run" if DRY_RUN else "profile update")
    logger.info("Location filter: %s", config.location)
    try:
        require_xray(config.xray_binary)
    except XrayProbeError as e:
        logger.error("%s; profile not changed", e)
        raise SystemExit(1) from None
    opener = download_opener(config.proxy)
    geoip = None
    if config.location == "europe":
        logger.info("Loading GeoIP databases (downloading or refreshing when needed)")
        try:
            geoip = GeoIP(config.geoip_ipv4_url, config.geoip_ipv6_url, config.geoip_cache_dir, opener)
        except GeoIPError as e:
            logger.error("%s; profile not changed", e)
            raise SystemExit(1) from None
    logger.info("Checking candidates with up to %d concurrent Xray processes", config.probe_concurrency)
    run_id = secrets.token_hex(4)
    candidates = select_outbounds(opener, geoip, run_id)
    if not candidates:
        logger.error("No outbounds passed location and connectivity checks; profile not changed")
        raise SystemExit(1)

    logger.info("Fetching profile")
    api = RemnawaveAPI(config.url, config.token, config.ssl_ctx)
    profile = api.get_profile(config.profile)
    cfg = profile.get("config", profile)
    if isinstance(cfg, str):
        cfg = json.loads(cfg)
    cfg = copy.deepcopy(cfg)

    try:
        os.makedirs(config.backup_dir, exist_ok=True)
        backup = os.path.join(config.backup_dir, f"{config.profile}-{datetime.now():%Y%m%d-%H%M%S}-{run_id}.json")
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
    except OSError:
        logger.error("Could not save profile backup; profile not changed")
        raise SystemExit(1) from None

    existing = cfg.get("outbounds", [])
    fixed = [o for o in existing if o.get("tag") in FIXED_TAGS]
    missing = set(FIXED_TAGS) - {o.get("tag") for o in fixed}
    if missing:
        logger.warning("Profile has no outbound(s): %s", ", ".join(sorted(missing)))
    others = [
        o for o in existing
        if o.get("tag") not in FIXED_TAGS and not str(o.get("tag", "")).startswith(TAG_PREFIX)
    ]
    logger.info("Backup saved to %s", backup)
    base_outbounds = fixed + others
    expected_outbounds = copy.deepcopy(existing)

    def publish(selection, stage):
        nonlocal expected_outbounds
        proposed = base_outbounds + [item[0] for item in selection]
        if DRY_RUN:
            logger.info("Dry run: would publish %s (%d outbounds)", stage, len(selection))
            return
        logger.info("Publishing %s (%d outbounds)", stage, len(selection))
        try:
            api.update_outbounds(config.profile, expected_outbounds, proposed)
        except ProfileConflictError:
            logger.error("Panel outbounds changed externally; stopping without overwriting them; backup: %s", backup)
            raise SystemExit(1) from None
        except SystemExit:
            logger.error("Panel update failed; the last confirmed profile may remain active; backup: %s", backup)
            raise
        expected_outbounds = copy.deepcopy(proposed)

    ranked = refine_outbounds(candidates, publish)
    logger.info("Best passing outbounds (ranked by download speed, then latency):")
    for rank, (outbound, subscription, latency, speed) in enumerate(ranked, 1):
        logger.info("#%d subscription %d | %s | %.2f Mbps | %.1f ms", rank, subscription,
                    outbound["tag"], speed.download_mbps, latency.latency_ms)
    if DRY_RUN:
        logger.info("Dry run complete; profile not updated (preview on stdout)")
        print(json.dumps([item[0] for item in ranked[:2]], indent=2))
    else:
        logger.info("Profile updated with %d speed-verified outbounds", len(ranked))


if __name__ == "__main__":
    configure_logging()
    main()

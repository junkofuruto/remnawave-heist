#!/usr/bin/env python3

import json, logging, os, re, secrets, sys, urllib.parse
from datetime import datetime

from downloads import download_opener
from environment import config
from geoip import GeoIP, GeoIPError
from logging_setup import configure_logging
from remnawave_api import RemnawaveAPI
from vless import fetch_subscription, link_to_outbound

logger = logging.getLogger("remnawave.main")

TAG_PREFIX = "out-auto-"
FIXED_TAGS = ("direct", "block")
MAX_OUTBOUNDS = 20
DRY_RUN = "--dry-run" in sys.argv

def main():
    logger.info("Starting %s", "dry run" if DRY_RUN else "profile update")
    logger.info("Location filter: %s", config.location)
    opener = download_opener(config.proxy)
    geoip = None
    if config.location == "europe":
        logger.info("Loading GeoIP databases (downloading or refreshing when needed)")
        try:
            geoip = GeoIP(config.geoip_ipv4_url, config.geoip_ipv6_url, config.geoip_cache_dir, opener)
        except GeoIPError as e:
            logger.error("%s; profile not changed", e)
            raise SystemExit(1) from None
    seen = set()
    run_id = secrets.token_hex(4)
    new_outbounds = []
    for index, url in enumerate(config.urls, 1):
        logger.info("Reading subscription %d/%d", index, len(config.urls))
        try:
            subscription_links = fetch_subscription(url, opener)
        except (OSError, ValueError):
            logger.error("Failed to read subscription %d", index)
            raise SystemExit(1) from None
        for link in subscription_links:
            if link in seen:
                continue
            seen.add(link)
            try:
                name = urllib.parse.unquote(urllib.parse.urlsplit(link).fragment) or "node"
                slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")[:20] or "node"
                tag = f"{TAG_PREFIX}{run_id}-{len(new_outbounds) + 1:02d}-{slug}"
                outbound = link_to_outbound(link, tag)
            except Exception:
                logger.warning("Skipping invalid VLESS link")
                continue
            address = outbound["settings"]["vnext"][0]["address"]
            if geoip is not None and not geoip.is_european(address):
                continue
            new_outbounds.append(outbound)
            if len(new_outbounds) == MAX_OUTBOUNDS:
                break
        if len(new_outbounds) == MAX_OUTBOUNDS:
            break
    if not new_outbounds:
        logger.error("No valid outbounds matched location filter '%s'; profile not changed", config.location)
        raise SystemExit(1)
    logger.info("Selected %d outbounds", len(new_outbounds))

    logger.info("Fetching profile")
    api = RemnawaveAPI(config.url, config.token, config.ssl_ctx)
    profile = api.get_profile(config.profile)
    cfg = profile.get("config", profile)
    if isinstance(cfg, str):
        cfg = json.loads(cfg)

    os.makedirs(config.backup_dir, exist_ok=True)
    backup = os.path.join(config.backup_dir, f"{config.profile}-{datetime.now():%Y%m%d-%H%M%S}.json")
    with open(backup, "w") as f:
        json.dump(profile, f, indent=2)

    existing = cfg.get("outbounds", [])
    fixed = [o for o in existing if o.get("tag") in FIXED_TAGS]
    missing = set(FIXED_TAGS) - {o.get("tag") for o in fixed}
    if missing:
        logger.warning("Profile has no outbound(s): %s", ", ".join(sorted(missing)))
    others = [
        o for o in existing
        if o.get("tag") not in FIXED_TAGS and not str(o.get("tag", "")).startswith(TAG_PREFIX)
    ]
    cfg["outbounds"] = fixed + others + new_outbounds

    logger.info("Removing old %s* outbounds, adding %d new", TAG_PREFIX, len(new_outbounds))
    logger.info("Backup saved to %s", backup)
    if DRY_RUN:
        logger.info("Dry run complete; profile not updated (preview on stdout)")
        print(json.dumps(new_outbounds[:2], indent=2))
        return

    logger.info("Updating profile")
    api.update_profile(config.profile, cfg)
    logger.info("Profile updated")


if __name__ == "__main__":
    configure_logging()
    main()

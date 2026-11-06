# Remnawave outbound updater

Copy `config.example.json` to `config.json`, restrict access to that file, and
fill in the panel `url`, API `token`, `profile` UUID, and the list of
subscription `urls`. The configuration file contains credentials and is ignored
by Git. Links from the subscriptions are combined in order, deduplicated, and
limited to 20 outbounds.

Configuration is loaded from `config.json` beside `environment.py`, regardless
of the current working directory. Set `REMNAWAVE_CONFIG_FILE` to select a
different JSON file. The `.env` file and individual application configuration
variables are not used. Standard proxy environment variables may affect downloads
when `proxy` is not set.

Optional JSON settings:

- `cert`: CA certificate file for panel requests. If omitted, Python's default
  TLS certificate verification is used.
- `backup_dir`: backup directory; defaults to `backups` beside the script.
- `proxy`: optional HTTP or SOCKS5 proxy URL for subscription and GeoIP
  downloads, for example `"http://127.0.0.1:8080"`, `"socks5://127.0.0.1:1080"`,
  or `"socks5h://user:password@proxy.example:1080"`. `socks5` resolves download
  hostnames locally; `socks5h` resolves them through the proxy. SOCKS5 supports
  no authentication or username/password authentication. Percent-encode special
  characters in credentials. SOCKS credentials travel to the proxy without
  transport encryption, so use a trusted network. Omit the setting or use `null`
  for Python's standard environment-proxy behavior (which does not add SOCKS
  support). Explicit proxies are used for both HTTP and HTTPS downloads, including
  hosts listed in `NO_PROXY`. HTTPS proxy URLs and SOCKS4 are not supported.
  Protect this file if it contains credentials.
  Panel API requests always bypass configured and environment proxies, and
  GeoIP outbound hostname resolution uses the local system resolver.
- `location`: `"europe"` (default) selects outbounds by IP country. Set it to
  `"all"` to disable GeoIP filtering.
- `geoip_ipv4_url` and `geoip_ipv6_url`: HTTPS URLs for IPv4 and IPv6
  country-range CSV files. Defaults use the daily-updated
  [sapics/ip-location-db server-country dataset](https://github.com/sapics/ip-location-db),
  licensed under PDDL. The expected format is `start_ip,end_ip,country_code`,
  sorted by address with non-overlapping inclusive ranges.
- `geoip_cache_dir`: download cache directory; defaults to `.geoip-cache` beside
  the script.

When Europe filtering is enabled, both databases are downloaded automatically
on first use and refreshed after 24 hours. Downloads are validated before the
cached file is replaced. If a refresh fails, the last valid cached file is used
with a warning; if no valid cache is available, the profile is left unchanged.
An internet connection is required for the first download, but no Tor installation
is needed. The source sees the requester's IP, but the server IPs being checked
are never sent to it. If you previously configured `geoip_ipv4` or `geoip_ipv6`
file paths, remove those obsolete keys and use the URL settings instead.

The outbound's address is looked up directly if it is an IP, or resolved through
system DNS if it is a hostname. Every returned IP must be public and match a
European country in the database; unknown, unresolved, private, and mixed-region
addresses are excluded. The Europe country-code allowlist in `geoip.py` includes
the UK, Russia, Turkey, and Cyprus. It is country-level, so a country spanning
continents may include locations outside Europe. GeoIP can be inaccurate or stale;
DNS answers may also change or differ where the panel runs. If a database cannot
be loaded or no outbounds match, the profile is left unchanged. Filtering happens
before the 20-outbound limit.

Explicit relative paths are interpreted relative to the current working
directory. Run `python3 main.py --dry-run` to inspect proposed outbound changes
without updating the panel. The dry run still fetches the profile and creates a
backup.

Progress, warnings, and errors are logged to stderr with timestamps and levels.
Terminal output uses color; set `NO_COLOR` to disable it. In dry-run mode, stdout
contains the JSON preview of up to two proposed outbounds. Treat that preview as
sensitive because it includes connection credentials. Configuration errors
reported before startup logging is initialized remain plain stderr messages.

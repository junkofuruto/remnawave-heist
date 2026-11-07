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
- `probe_urls`: non-empty list of HTTPS URLs to check through every candidate
  outbound. Defaults to `https://telegram.org/` and `https://www.instagram.com/`.
  Every URL must return HTTP 2xx; redirects, blocked responses, timeouts, TLS
  errors, and other failures reject the candidate. Choose URLs that are stable
  and suitable for your network. Each checked outbound produces one result line
  containing its generated tag and successful probes. Failures also identify the
  first failed probe by position and hostname (and port, if specified); URL paths
  and query parameters are not logged. Later probes are not attempted for that
  candidate.
- `probe_timeout`: timeout in seconds for each probe request (default 10, maximum
  120). Multiple candidates and URLs can make a run take several minutes.
- `probe_concurrency`: maximum number of candidate outbounds checked in parallel
  (default 4, range 1–32). Each active check starts its own Xray process; probe
  URLs for an individual outbound remain sequential. Results retain subscription
  order, though log lines appear as checks complete. The 20-outbound limit also
  limits the number of simultaneous candidate checks.
- `xray_binary`: Xray executable name or path (default `xray`). Xray must be
  installed and accessible to the user running the updater.
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
Errors include a sanitized reason such as an HTTP status, DNS failure, proxy
protocol error, or TLS failure. If a checker uses an HTTP proxy, configure the
same HTTP proxy in this tool rather than a SOCKS URL; for SOCKS5 remote DNS,
use `socks5h://`. The checker and this application can have different settings.
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

Each location-matched candidate is checked before being added. A temporary Xray
process receives the candidate configuration through an anonymous temporary file
and exposes a randomly assigned, password-protected SOCKS inbound on loopback.
Probe requests go through that inbound and the candidate, not the configured
subscription-download proxy. All probe URLs must succeed. The Xray process is
stopped after each candidate; if Xray cannot be started or no candidates pass,
the panel profile is left unchanged. Dry runs perform these checks too. Probe
URLs must be HTTPS and the local system's default trust store must trust their
certificates.

Explicit relative paths are interpreted relative to the current working
directory. Run `python3 main.py --dry-run` to inspect proposed outbound changes
without updating the panel. The dry run still fetches the profile and creates a
backup.

Progress, warnings, and errors are logged to stderr with abbreviated levels and
millisecond timestamps, for example `[INF] 12:34:56.010 | message`.
Terminal output uses color; set `NO_COLOR` to disable it. In dry-run mode, stdout
contains the JSON preview of up to two proposed outbounds. Treat that preview as
sensitive because it includes connection credentials. Configuration errors
reported before startup logging is initialized remain plain stderr messages.

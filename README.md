# Remnawave outbound updater

Copy `config.example.json` to `config.json`, restrict access to that file, and
fill in the panel `url`, API `token`, `profile` UUID, and the list of
subscription `urls`. The configuration file contains credentials and is ignored
by Git. A persistent pool tracks normalized outbound hashes, subscription
membership, connectivity, latency, and optional speed measurements.

Configuration is loaded from `config.json` beside `environment.py`, regardless
of the current working directory. Set `REMNAWAVE_CONFIG_FILE` to select a
different JSON file. The `.env` file and individual application configuration
variables are not used. Standard proxy environment variables may affect downloads
when `proxy` is not set.

Optional JSON settings:

- `cert`: CA certificate file for panel requests. If omitted, Python's default
  TLS certificate verification is used.
- `backup_dir`: backup directory; defaults to `backups` beside the script.
- `log_file`: path to the rotating log file, defaulting to
  `logs/remnawave.log` beside the script. Explicit relative paths use the current
  working directory. Files are restricted to the current user and rotate at
  5 MiB with three backups; keep custom log paths out of version control. File
  logging is intended for one updater process at a time; concurrent runs must use
  separate log files.
- `probe_urls`: non-empty list of HTTPS probes checked through every candidate.
  Entries use `"ranges URL"`, for example
  `"200-299|400-499 https://example.com/path"`. Ranges are inclusive,
  three-digit HTTP status codes from 100 to 599; separate multiple ranges with
  `|`. A plain HTTPS URL is also accepted and defaults to `200-299`. Defaults
  are `https://telegram.org/` and `https://www.instagram.com/`.
  Every probe must return a status in its allowed ranges; other statuses,
  timeouts, TLS errors, and other failures reject the candidate. Redirects are
  not followed; permit `300-399` explicitly if those responses are acceptable.
  Choose URLs that are stable and suitable for your network. Each checked
  outbound produces one result line containing its generated tag and successful
  probes. Failures identify all failed probes by position and hostname (and port,
  if specified); URL paths and query parameters are not logged. All configured
  status probes are attempted unless the Xray process exits.
- `probe_attempts`: total connectivity attempts per outbound, including the
  first attempt (default 3, range 1–10). A candidate is considered unavailable
  only after all attempts fail; Xray setup errors abort the run.
- `state_file`: persistent state path, default `state.json` beside the script.
  It contains full outbound connection details and credentials; it is created
  with mode `0600`. Keep custom state paths and their `.lock` files private and
  out of version control. If the state file is lost while the panel still has
  managed outbounds, bootstrap requires a successful subscription refresh and
  probes; back up this file securely. If there are duplicate managed outbounds,
  matching configurations are reconciled by hash after a successful refresh;
  an explicitly referenced panel tag is preserved where possible, otherwise the
  first existing panel tag is retained. Reconciliation stops if removing a tag
  would break another explicit routing-rule reference.
- `probe_timeout`: timeout in seconds for each probe request (default 10, maximum
  120). Multiple candidates and URLs can make a run take several minutes.
- `probe_concurrency`: maximum number of candidate outbounds checked in parallel
  (default 4, range 1–32). Each active check starts its own Xray process; probe
  URLs for an individual outbound remain sequential. Saved configurations are
  checked first, then newly discovered configurations. Speed checks are performed
  for newly discovered passing configurations; logs appear in completion order. Checks can
  consume significant bandwidth and time.
- `max_outbounds`: maximum number of best passing candidates to add to the
  profile (default 20, range 1–1000).
- `speed_test_url`: HTTPS URL serving at least `speed_test_bytes` bytes, default
  `https://speed.cloudflare.com/__down?bytes=1000000`. It must return HTTP 200 or
  206; redirects and shorter responses fail the speed check. The target receives
  the outbound server's IP. Change it if unavailable or unsuitable.
- `speed_test_bytes`: bytes to download per candidate (default 1,000,000; range
  1–100,000,000). Match the server URL's payload size to this value. A Range
  request is sent and at most this many bytes are read; a server that ignores the
  header may send additional data before the connection closes.
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
the UK, Turkey, and Cyprus but excludes Russia. It is country-level, so a country
spanning continents may include locations outside Europe. GeoIP can be inaccurate or stale;
DNS answers may also change or differ where the panel runs. If a database cannot
be loaded or no outbounds match, the profile is left unchanged. Filtering happens
before the configured outbound limit.

Each location-matched candidate is checked before being added. A temporary Xray
process receives the candidate configuration through an anonymous temporary file
and exposes a randomly assigned, password-protected SOCKS inbound on loopback.
Probe requests go through that inbound and the candidate, not the configured
subscription-download proxy. Each run has two routines. First, all saved active
and reserve outbounds are rechecked with the configured retry count, and failed
active entries are replaced from the healthy saved pool when possible. Second,
subscriptions are refreshed and newly discovered configurations are checked. A
saved configuration that is absent from all successfully refreshed sources is
removed and replaced if a healthy candidate is available. Invalid individual
VLESS entries are skipped; if a subscription contains any invalid entries,
previously saved entries from that source are retained until a clean refresh.
A failed, empty, or wholly invalid subscription aborts the refresh without
removals; a completed first-routine health update may already have been applied.

Configuration identity is SHA-256 of canonical outbound JSON excluding its tag;
subscription identities are hashes of their URLs. The state stores full outbound
credentials, measurements, last-check timestamps, and source membership. Saved
entries that fail all attempts are retained as unhealthy with their last
successful latency and checked again on a later run. Healthy active entries
remain selected; vacancies are filled by saved speed (when available), then
latency. New passing configurations are eligible as
soon as discovered. If no healthy replacement exists, the current panel profile
is left unchanged, even if it contains an unhealthy or removed outbound.

Latency is the average time from starting the SOCKS connection to receiving HTTP
headers across the status probe requests; the same requests check connectivity,
so no second latency round is needed. Download speed
is measured in Mbps over the whole speed request, including connection setup and
time to first byte. The final report lists selected outbounds and their source
subscription numbers. Duplicate configurations track all source subscriptions.
Measurements are approximate and concurrent tests share available bandwidth;
speed-check failure does not make an otherwise healthy outbound ineligible.

Every panel update is preceded by a private backup and a persistent pending-update
record. On restart, an interrupted update is reconciled against the panel; if
the result does not match either expected state, the script stops for manual
reconciliation. A file lock prevents concurrent non-dry-run updaters using the
same state file. Before each update, current panel outbounds are re-read and
compared with the last observed profile; external changes stop the run. Other
fields are refreshed, but the API update is not atomic, so edits between read and
write can still be overwritten. Avoid editing the profile while this script runs.
Dry runs check the current state but do not modify state or panel. Probe URLs must
be HTTPS and their certificates trusted by the local system. Linux `/proc` access
is needed to verify each temporary listening port belongs to its Xray process.

Explicit relative paths are interpreted relative to the current working
directory. Run `python3 main.py --dry-run` to inspect proposed outbound changes
without updating the panel or persistent state.

Progress, warnings, and errors are logged to stderr and the configured rotating
file with abbreviated levels and millisecond timestamps, for example
`[INF] 12:34:56.010 | message`. Terminal level badges have background colors;
set `NO_COLOR` to disable them. Files and redirected output contain no ANSI colors.
Startup configuration errors occur before the file logger is initialized.
In dry-run mode, stdout contains the JSON preview of up to two proposed
outbounds. Treat that preview as sensitive because it includes connection credentials.

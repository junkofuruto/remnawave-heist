import json
import os
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.parse import unquote, urlsplit

from geoip import DEFAULT_GEOIP_IPV4_URL, DEFAULT_GEOIP_IPV6_URL
from xray_probe import parse_probe_entry

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = Path(os.environ.get("REMNAWAVE_CONFIG_FILE", BASE_DIR / "config.json"))


@dataclass
class Config:
    url: str
    token: str = field(repr=False)
    profile: str
    urls: List[str] = field(repr=False)
    cert: Optional[Path] = None
    backup_dir: Path = BASE_DIR / "backups"
    location: str = "europe"
    geoip_ipv4_url: str = DEFAULT_GEOIP_IPV4_URL
    geoip_ipv6_url: str = DEFAULT_GEOIP_IPV6_URL
    geoip_cache_dir: Path = BASE_DIR / ".geoip-cache"
    proxy: Optional[str] = field(default=None, repr=False)
    probe_urls: List[str] = field(default_factory=lambda: ["200-299 https://telegram.org/", "200-299 https://www.instagram.com/"], repr=False)
    probe_timeout: float = 10
    probe_concurrency: int = 4
    xray_binary: str = "xray"
    ssl_ctx: Optional[ssl.SSLContext] = field(init=False, default=None, repr=False)

    def __post_init__(self):
        self.url = self.url.rstrip("/")
        if self.cert is not None:
            self.ssl_ctx = ssl.create_default_context(cafile=str(self.cert))
            self.ssl_ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT


def load_config(path: Path) -> Config:
    try:
        with path.open(encoding="utf-8") as config_file:
            data = json.load(config_file)
    except FileNotFoundError:
        sys.exit(f"config file not found: {path}")
    except (OSError, UnicodeError, json.JSONDecodeError) as e:
        sys.exit(f"cannot read config file {path}: {e}")

    if not isinstance(data, dict):
        sys.exit(f"config file must contain a JSON object: {path}")

    for key in ("url", "token", "profile"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            sys.exit(f"config value {key} must be a non-empty string")
    urls = data.get("urls")
    if not isinstance(urls, list) or not urls or any(
        not isinstance(url, str) or not url.strip() for url in urls
    ):
        sys.exit("config value urls must be a non-empty list of non-empty strings")
    for key in ("cert", "backup_dir", "geoip_cache_dir", "geoip_ipv4_url", "geoip_ipv6_url"):
        if key in data and (not isinstance(data[key], str) or not data[key].strip()):
            sys.exit(f"config value {key} must be a non-empty string")

    for key in ("geoip_ipv4", "geoip_ipv6"):
        if key in data:
            sys.exit(f"config value {key} is obsolete; use {key}_url instead")
    for key in ("geoip_ipv4_url", "geoip_ipv6_url"):
        if key in data:
            try:
                parsed = urlsplit(data[key])
                valid = (parsed.scheme == "https" and bool(parsed.hostname)
                         and not parsed.username and not parsed.password and not any(ch.isspace() for ch in data[key]))
            except ValueError:
                valid = False
            if not valid:
                sys.exit(f"config value {key} must be an HTTPS URL without embedded credentials")

    proxy = data.get("proxy")
    if proxy is not None:
        try:
            parsed_proxy = urlsplit(proxy) if isinstance(proxy, str) else None
            valid_proxy = bool(
                parsed_proxy and parsed_proxy.scheme in ("http", "socks5", "socks5h") and parsed_proxy.hostname
                and parsed_proxy.port and not parsed_proxy.path and not parsed_proxy.query
                and not parsed_proxy.fragment and not any(ch.isspace() for ch in proxy)
            )
            if valid_proxy and parsed_proxy.scheme in ("socks5", "socks5h") and parsed_proxy.username is not None:
                username = unquote(parsed_proxy.username).encode("utf-8")
                password = unquote(parsed_proxy.password or "").encode("utf-8")
                valid_proxy = 1 <= len(username) <= 255 and 1 <= len(password) <= 255
        except (ValueError, UnicodeError):
            valid_proxy = False
        if not valid_proxy:
            sys.exit("config value proxy must be null or an HTTP/SOCKS5 proxy URL with host and port")

    location = data.get("location", "europe")
    if not isinstance(location, str) or location not in ("europe", "all"):
        sys.exit("config value location must be 'europe' or 'all'")

    probe_urls = data.get("probe_urls", ["200-299 https://telegram.org/", "200-299 https://www.instagram.com/"])
    if not isinstance(probe_urls, list) or not probe_urls:
        sys.exit("config value probe_urls must be a non-empty list of probe entries")
    for index, probe_entry in enumerate(probe_urls, 1):
        try:
            parse_probe_entry(probe_entry)
        except ValueError as e:
            sys.exit(f"config value probe_urls entry {index}: {e}")
    probe_timeout = data.get("probe_timeout", 10)
    if isinstance(probe_timeout, bool) or not isinstance(probe_timeout, (int, float)) or not 0 < probe_timeout <= 120:
        sys.exit("config value probe_timeout must be a number between 0 and 120 seconds")
    probe_concurrency = data.get("probe_concurrency", 4)
    if isinstance(probe_concurrency, bool) or not isinstance(probe_concurrency, int) or not 1 <= probe_concurrency <= 32:
        sys.exit("config value probe_concurrency must be an integer between 1 and 32")
    xray_binary = data.get("xray_binary", "xray")
    if not isinstance(xray_binary, str) or not xray_binary.strip() or "\0" in xray_binary:
        sys.exit("config value xray_binary must be a non-empty executable name or path")

    return Config(
        url=data["url"],
        token=data["token"],
        profile=data["profile"],
        urls=urls,
        cert=Path(data["cert"]) if "cert" in data else None,
        backup_dir=Path(data.get("backup_dir", BASE_DIR / "backups")),
        location=location,
        geoip_ipv4_url=data.get("geoip_ipv4_url", DEFAULT_GEOIP_IPV4_URL),
        geoip_ipv6_url=data.get("geoip_ipv6_url", DEFAULT_GEOIP_IPV6_URL),
        geoip_cache_dir=Path(data.get("geoip_cache_dir", BASE_DIR / ".geoip-cache")),
        proxy=proxy,
        probe_urls=probe_urls,
        probe_timeout=probe_timeout,
        probe_concurrency=probe_concurrency,
        xray_binary=xray_binary,
    )


config = load_config(CONFIG_FILE)


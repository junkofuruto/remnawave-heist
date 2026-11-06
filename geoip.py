import bisect
import hashlib
import ipaddress
import logging
import os
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPException
from array import array
from pathlib import Path

from downloads import download_opener


logger = logging.getLogger("remnawave.geoip")
GEOIP_CACHE_SECONDS = 24 * 60 * 60
MAX_GEOIP_BYTES = 128 * 1024 * 1024

DEFAULT_GEOIP_IPV4_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/server-country/server-country-ipv4.csv"
DEFAULT_GEOIP_IPV6_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/server-country/server-country-ipv6.csv"

EUROPE_COUNTRY_CODES = frozenset(
    "AL AD AT BY BE BA BG HR CY CZ DK EE FI FR DE GR HU IS IE IT XK LV LI LT LU "
    "MT MD MC ME NL MK NO PL PT RO RU SM RS SK SI ES SE CH TR UA GB VA".split()
)


class GeoIPError(Exception):
    pass


class CountryDatabase:
    """Read sorted IP range and country code CSV data."""

    def __init__(self, path, version):
        self.version = version
        self.starts = array("I") if version == 4 else []
        self.ends = array("I") if version == 4 else []
        self.countries = []
        try:
            with Path(path).open(encoding="utf-8") as source:
                for number, raw in enumerate(source, 1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        start, end, country = (part.strip().strip('"') for part in line.split(","))
                        address_type = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
                        start = int(address_type(int(start) if start.isdecimal() else start))
                        end = int(address_type(int(end) if end.isdecimal() else end))
                        if start > end:
                            raise ValueError("invalid IP range")
                        if not (len(country) == 2 and (country == "??" or country.isascii() and country.isalpha())):
                            raise ValueError("invalid country code")
                        if self.ends and start <= self.ends[-1]:
                            raise ValueError("ranges must be sorted and non-overlapping")
                    except ValueError as e:
                        raise GeoIPError(f"invalid IPv{version} GeoIP data at line {number}") from e
                    self.starts.append(start)
                    self.ends.append(end)
                    self.countries.append(country.upper())
        except (OSError, UnicodeError) as e:
            raise GeoIPError(f"cannot read IPv{version} GeoIP database: {path}") from e
        if not self.starts:
            raise GeoIPError(f"IPv{version} GeoIP database is empty: {path}")

    def country(self, address):
        if address.version != self.version:
            return None
        value = int(address)
        index = bisect.bisect_right(self.starts, value) - 1
        if index >= 0 and value <= self.ends[index]:
            country = self.countries[index]
            return None if country == "??" else country
        return None


def load_downloaded_database(url, version, cache_dir, opener=None):
    """Download and validate a database atomically, retaining a valid stale cache on failure."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as e:
        raise GeoIPError(f"invalid IPv{version} GeoIP URL") from e
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or any(ch.isspace() for ch in url)):
        raise GeoIPError(f"IPv{version} GeoIP URL must be HTTPS without embedded credentials")
    cache_dir = Path(cache_dir)
    cache_key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    cache = cache_dir / f"geoip-ipv{version}-{cache_key}.csv"
    cached = None
    try:
        if cache.is_file():
            cached = CountryDatabase(cache, version)
            if 0 <= time.time() - cache.stat().st_mtime < GEOIP_CACHE_SECONDS:
                return cached
    except (OSError, GeoIPError):
        cached = None

    logger.info("Downloading IPv%d GeoIP database", version)
    temporary = None
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="wb", dir=cache_dir, prefix=".geoip-", delete=False) as output:
            temporary = Path(output.name)
            request = urllib.request.Request(url, headers={"User-Agent": "remnawave-geoip/1.0"})
            with (opener or download_opener()).open(request, timeout=30) as response:
                final_url = response.geturl() if hasattr(response, "geturl") else url
                if urllib.parse.urlsplit(final_url).scheme != "https":
                    raise GeoIPError(f"IPv{version} GeoIP download redirected to an insecure URL")
                expected_length = response.headers.get("Content-Length") if hasattr(response, "headers") else None
                if expected_length is not None and (not expected_length.isdecimal() or int(expected_length) > MAX_GEOIP_BYTES):
                    raise GeoIPError(f"invalid IPv{version} GeoIP download size")
                total = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_GEOIP_BYTES:
                        raise GeoIPError(f"IPv{version} GeoIP download is too large")
                    output.write(chunk)
                if expected_length is not None and total != int(expected_length):
                    raise GeoIPError(f"incomplete IPv{version} GeoIP download")
        database = CountryDatabase(temporary, version)
        os.replace(temporary, cache)
        temporary = None
        logger.info("Updated IPv%d GeoIP database", version)
        return database
    except (OSError, ValueError, GeoIPError, HTTPException) as e:
        if isinstance(e, urllib.error.HTTPError):
            e.close()
        if cached is not None:
            logger.warning("Could not refresh IPv%d GeoIP database; using cached copy", version)
            return cached
        raise GeoIPError(f"cannot download or load IPv{version} GeoIP database") from e
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove temporary IPv%d GeoIP download", version)


class GeoIP:
    def __init__(self, ipv4_url, ipv6_url, cache_dir, opener=None):
        self.ipv4 = load_downloaded_database(ipv4_url, 4, cache_dir, opener)
        self.ipv6 = load_downloaded_database(ipv6_url, 6, cache_dir, opener)
        self.cache = {}

    def is_european(self, hostname):
        if not hostname or "%" in hostname:
            return False
        if hostname in self.cache:
            return self.cache[hostname]
        try:
            try:
                addresses = {ipaddress.ip_address(hostname)}
            except ValueError:
                records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
                addresses = {ipaddress.ip_address(record[4][0]) for record in records}
            result = bool(addresses) and all(
                address.is_global and (self.ipv4 if address.version == 4 else self.ipv6).country(address)
                in EUROPE_COUNTRY_CODES for address in addresses
            )
        except (OSError, ValueError):
            result = False
        self.cache[hostname] = result
        return result

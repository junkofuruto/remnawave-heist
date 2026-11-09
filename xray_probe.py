import http.client
import json
import logging
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse

from contextlib import contextmanager
from dataclasses import dataclass
from http.client import HTTPException

from downloads import _socks5_connect

logger = logging.getLogger("remnawave.probe")
STARTUP_TIMEOUT = 5


DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
DEFAULT_SPEED_BYTES = 1_000_000


@dataclass(frozen=True)
class LatencyResult:
    latency_ms: float


@dataclass(frozen=True)
class SpeedResult:
    download_mbps: float
    download_bytes: int
    speed_seconds: float


def parse_probe_entry(entry):
    """Parse an HTTPS probe with optional inclusive HTTP status ranges."""
    if not isinstance(entry, str) or entry != entry.strip():
        raise ValueError("probe entry must be a string without leading or trailing whitespace")
    parts = entry.split()
    if len(parts) == 1:
        ranges_text, url = "200-299", parts[0]
    elif len(parts) == 2:
        ranges_text, url = parts
    else:
        raise ValueError("probe entry must contain ranges followed by an HTTPS URL")
    ranges = []
    for item in ranges_text.split("|"):
        match = re.fullmatch(r"([0-9]{3})-([0-9]{3})", item)
        if not match:
            raise ValueError("invalid probe status range")
        low, high = map(int, match.groups())
        if not 100 <= low <= high <= 599:
            raise ValueError("probe status range must be between 100 and 599")
        ranges.append((low, high))
    try:
        parsed = urllib.parse.urlsplit(url)
        valid = (parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username
                 and not parsed.password and not parsed.fragment and not any(ch.isspace() for ch in url))
        port = parsed.port
        valid = valid and (port is None or 1 <= port <= 65535)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("probe URL must be a valid HTTPS URL without credentials or a fragment")
    return url, tuple(ranges)


def _probe_label(url):
    """Identify the probe without logging credentials, paths, or query parameters."""
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or "unknown"
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    return f"{host}:{port}" if port is not None else host


def _outbound_label(outbound):
    """Use only the generated tag and avoid logging credentials or control characters."""
    tag = outbound.get("tag")
    if not isinstance(tag, str):
        return "unknown"
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", tag)[:80] or "unknown"


def _probe_url(proxy, url, timeout, context, max_bytes=0):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    port = parsed.port or 443
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    started = time.monotonic()
    raw = _socks5_connect(proxy, host, port, timeout)
    try:
        connection.sock = context.wrap_socket(raw, server_hostname=host)
        headers = {"User-Agent": "remnawave-outbound-check/1.0", "Connection": "close",
                   "Accept-Encoding": "identity"}
        if max_bytes:
            headers["Range"] = f"bytes=0-{max_bytes - 1}"
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        latency = time.monotonic() - started
        if latency > timeout:
            raise TimeoutError("probe timed out")
        size = 0
        expected_length = None
        if max_bytes and response.status in (200, 206):
            if response.length is not None:
                expected_length = min(response.length, max_bytes)
            sock = connection.sock or getattr(getattr(response, "fp", None), "raw", None)
            if sock is not None and not hasattr(sock, "settimeout"):
                sock = getattr(sock, "_sock", None)
            if sock is None:
                raise OSError("speed test socket unavailable")
            while size < max_bytes:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError("speed probe timed out")
                sock.settimeout(remaining)
                chunk = response.read1(min(65536, max_bytes - size))
                if not chunk:
                    break
                size += len(chunk)
            if time.monotonic() - started > timeout:
                raise TimeoutError("speed probe timed out")
        if expected_length is not None and size < expected_length:
            raise http.client.IncompleteRead(b"", expected_length - size)
        return response.status, latency, size, time.monotonic() - started
    finally:
        connection.close()
        raw.close()


class XrayProbeError(Exception):
    pass


def require_xray(binary):
    if not shutil.which(binary):
        raise XrayProbeError("Xray executable not found; set xray_binary or install Xray")


def _available_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _xray_listens_on(process, port):
    """Verify that the ready TCP listener belongs to this Xray process (Linux)."""
    inodes = set()
    try:
        for fd in os.listdir(f"/proc/{process.pid}/fd"):
            try:
                target = os.readlink(f"/proc/{process.pid}/fd/{fd}")
            except FileNotFoundError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(target[8:-1])
        with open(f"/proc/{process.pid}/net/tcp", encoding="ascii") as table:
            for row in table:
                fields = row.split()
                if len(fields) > 9 and fields[1] == f"0100007F:{port:04X}" and fields[3] == "0A":
                    if fields[9] in inodes:
                        return True
    except OSError as e:
        raise XrayProbeError("cannot verify local Xray listener ownership") from e
    return False


def _stop(process):
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        else:
            process.wait()
    except ProcessLookupError:
        process.wait()


@contextmanager
def _xray_session(outbound, binary):
    description = _outbound_label(outbound)
    try:
        port = _available_port()
    except OSError as e:
        raise XrayProbeError("cannot allocate a local Xray probe port") from e
    username, password = secrets.token_hex(16), secrets.token_hex(16)
    xray_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"auth": "password", "accounts": [{"user": username, "pass": password}],
                                   "udp": False}}],
        "outbounds": [outbound],
    }
    try:
        with tempfile.TemporaryFile(mode="w+b") as config_file:
            config_file.write(json.dumps(xray_config).encode("utf-8"))
            config_file.seek(0)
            process = subprocess.Popen([binary, "run", "-config", "stdin:"], stdin=config_file,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        raise XrayProbeError("cannot prepare or start Xray executable") from e
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if process.poll() is not None:
                logger.warning("Outbound %s: Xray exited before the probe inbound was ready", description)
                yield None
                return
            try:
                if _xray_listens_on(process, port):
                    break
            except XrayProbeError:
                if process.poll() is not None:
                    logger.warning("Outbound %s: Xray exited before the probe inbound was ready", description)
                    yield None
                    return
                raise
            time.sleep(0.05)
        else:
            logger.warning("Outbound %s: Xray probe inbound did not start in time", description)
            yield None
            return
        if process.poll() is not None:
            logger.warning("Outbound %s: Xray exited before probing", description)
            yield None
            return
        try:
            context = ssl.create_default_context()
        except OSError as e:
            raise XrayProbeError("cannot initialize TLS for outbound probes") from e
        yield process, f"socks5h://{username}:{password}@127.0.0.1:{port}", context
    finally:
        _stop(process)




def check_outbound(outbound, urls, timeout=10, binary="xray"):
    """Check connectivity, then measure latency only for passing candidates."""
    if not urls:
        raise XrayProbeError("at least one outbound probe URL is required")
    try:
        probes = [parse_probe_entry(entry) for entry in urls]
    except ValueError as e:
        raise XrayProbeError("invalid outbound probe configuration") from e
    description = _outbound_label(outbound)
    with _xray_session(outbound, binary) as session:
        if session is None:
            return None
        process, proxy, context = session
        passed_probes, failed_probes = [], []
        for index, (url, ranges) in enumerate(probes, 1):
            label = _probe_label(url)
            try:
                status, _, _, _ = _probe_url(proxy, url, timeout, context)
                failure = None if any(low <= status <= high for low, high in ranges) else f"returned HTTP {status}"
            except TimeoutError:
                failure = "timed out"
            except ssl.SSLCertVerificationError:
                failure = "failed TLS certificate verification"
            except (OSError, ValueError, HTTPException):
                failure = "failed"
            if process.poll() is not None:
                logger.warning("Outbound %s: Xray exited during probe %d (%s)", description, index, label)
                return None
            if failure:
                failed_probes.append(f"{index} ({label}) {failure}")
            else:
                passed_probes.append(f"{index} ({label}, HTTP {status})")
        if failed_probes:
            logger.warning("Outbound %s: failed probes: %s; passed: %s", description,
                           ", ".join(failed_probes), ", ".join(passed_probes) or "none")
            return None
        latencies = []
        for index, (url, ranges) in enumerate(probes, 1):
            try:
                status, latency, _, _ = _probe_url(proxy, url, timeout, context)
            except (OSError, ValueError, HTTPException):
                logger.warning("Outbound %s: latency check %d (%s) failed", description, index, _probe_label(url))
                return None
            if process.poll() is not None or not any(low <= status <= high for low, high in ranges):
                logger.warning("Outbound %s: latency check %d (%s) failed", description, index, _probe_label(url))
                return None
            latencies.append(latency)
        latency_ms = sum(latencies) * 1000 / len(latencies)
        logger.info("Outbound %s: latency %.1f ms; passed probes: %s", description, latency_ms, ", ".join(passed_probes))
        return LatencyResult(latency_ms)


def check_speed(outbound, speed_url=DEFAULT_SPEED_URL, speed_bytes=DEFAULT_SPEED_BYTES, timeout=10, binary="xray"):
    """Measure download speed through a fresh isolated Xray process."""
    try:
        parsed_speed_url, _ = parse_probe_entry(speed_url)
        if parsed_speed_url != speed_url:
            raise ValueError
    except ValueError as e:
        raise XrayProbeError("invalid speed test URL") from e
    if isinstance(speed_bytes, bool) or not isinstance(speed_bytes, int) or speed_bytes < 1:
        raise XrayProbeError("invalid speed test size")
    description = _outbound_label(outbound)
    with _xray_session(outbound, binary) as session:
        if session is None:
            return None
        process, proxy, context = session
        speed_label = _probe_label(speed_url)
        try:
            status, _, size, duration = _probe_url(proxy, speed_url, timeout, context, speed_bytes)
            if status not in (200, 206):
                logger.warning("Outbound %s: speed check (%s) returned HTTP %d", description, speed_label, status)
                return None
            if size < speed_bytes:
                logger.warning("Outbound %s: speed check (%s) returned %d/%d bytes", description, speed_label, size, speed_bytes)
                return None
        except (OSError, ValueError, HTTPException):
            logger.warning("Outbound %s: speed check (%s) failed", description, speed_label)
            return None
        if process.poll() is not None or duration <= 0:
            logger.warning("Outbound %s: Xray exited or speed duration was invalid", description)
            return None
        mbps = size * 8 / duration / 1_000_000
        logger.info("Outbound %s: download %.2f Mbps", description, mbps)
        return SpeedResult(mbps, size, duration)

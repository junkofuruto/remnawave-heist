import http.client
import json
import logging
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse

from http.client import HTTPException

from downloads import _socks5_connect

logger = logging.getLogger("remnawave.probe")
STARTUP_TIMEOUT = 5


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


def _probe_url(proxy, url, timeout, context):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    port = parsed.port or 443
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    raw = _socks5_connect(proxy, host, port, timeout)
    try:
        connection.sock = context.wrap_socket(raw, server_hostname=host)
        connection.request("GET", path, headers={"User-Agent": "remnawave-outbound-check/1.0",
                                                  "Connection": "close"})
        return connection.getresponse().status
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


def check_outbound(outbound, urls, timeout=10, binary="xray"):
    """Return true only if every HTTPS probe returns an allowed status."""
    if not urls:
        raise XrayProbeError("at least one outbound probe URL is required")
    try:
        probes = [parse_probe_entry(entry) for entry in urls]
    except ValueError as e:
        raise XrayProbeError("invalid outbound probe configuration") from e
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
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            logger.warning("Outbound %s: Xray probe inbound did not start in time", description)
            return False
        if process.poll() is not None:
            logger.warning("Outbound %s: Xray exited before probing", description)
            return False
        proxy = f"socks5h://{username}:{password}@127.0.0.1:{port}"
        try:
            context = ssl.create_default_context()
        except OSError as e:
            raise XrayProbeError("cannot initialize TLS for outbound probes") from e
        passed_probes = []
        for index, (url, ranges) in enumerate(probes, 1):
            label = _probe_label(url)
            try:
                status = _probe_url(proxy, url, timeout, context)
                if not any(low <= status <= high for low, high in ranges):
                    logger.warning("Outbound %s: probe %d (%s) returned HTTP %d; passed: %s",
                                   description, index, label, status, ", ".join(passed_probes) or "none")
                    return False
            except (OSError, ValueError, HTTPException):
                logger.warning("Outbound %s: probe %d (%s) failed; passed: %s",
                               description, index, label, ", ".join(passed_probes) or "none")
                return False
            if process.poll() is not None:
                logger.warning("Outbound %s: Xray exited during probe %d (%s); passed: %s",
                               description, index, label, ", ".join(passed_probes) or "none")
                return False
            passed_probes.append(f"{index} ({label}, HTTP {status})")
        logger.info("Outbound %s: passed probes: %s", description, ", ".join(passed_probes))
        return True
    finally:
        _stop(process)

import copy
import fcntl
import hashlib
import json
import math
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path


class StateError(Exception):
    pass


def outbound_hash(outbound):
    content = copy.deepcopy(outbound)
    content.pop("tag", None)
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def subscription_hash(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def load_state(path, panel_url, profile, *, restrict_permissions=True):
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as source:
            state = json.load(source)
    except FileNotFoundError:
        return {"version": 1, "panel": subscription_hash(panel_url), "profile": profile, "outbounds": {}}
    except (OSError, UnicodeError, ValueError) as e:
        raise StateError("cannot read persistent state") from e
    if not isinstance(state, dict) or state.get("version") != 1:
        raise StateError("persistent state is invalid or has an unsupported version")
    if state.get("panel") != subscription_hash(panel_url) or state.get("profile") != profile:
        raise StateError("persistent state belongs to another panel/profile")
    if not isinstance(state.get("outbounds"), dict):
        raise StateError("persistent state contains an invalid outbound collection")
    pending = state.get("pending")
    if pending is not None and (not isinstance(pending, dict)
                                or not isinstance(pending.get("previous"), list)
                                or not isinstance(pending.get("proposed"), list)
                                or not isinstance(pending.get("previous_records", {}), dict)):
        raise StateError("persistent state contains an invalid pending update")
    if pending is not None:
        for digest, record in pending.get("previous_records", {}).items():
            if not isinstance(record, dict) or not isinstance(record.get("outbound"), dict):
                raise StateError("persistent state contains invalid pending records")
            try:
                previous_hashes = {outbound_hash(item) for item in pending["previous"] if isinstance(item, dict)}
                if outbound_hash(record["outbound"]) != digest or digest not in previous_hashes:
                    raise StateError("persistent state contains invalid pending records")
            except (ValueError, TypeError, RecursionError) as e:
                raise StateError("persistent state contains invalid pending records") from e
    if restrict_permissions:
        try:
            os.chmod(path, 0o600)
        except OSError as e:
            raise StateError("cannot restrict persistent state permissions") from e
    for key, item in state["outbounds"].items():
        if not isinstance(item, dict) or not isinstance(item.get("outbound"), dict):
            raise StateError("persistent state contains an invalid outbound")
        try:
            destination = item["outbound"]["settings"]["vnext"][0]
            valid_destination = (isinstance(item["outbound"].get("tag"), str)
                                 and item["outbound"]["tag"].startswith("out-auto-")
                                 and item["outbound"].get("protocol") == "vless"
                                 and isinstance(destination["address"], str) and bool(destination["address"])
                                 and isinstance(destination["port"], int) and not isinstance(destination["port"], bool)
                                 and 1 <= destination["port"] <= 65535
                                 and isinstance(destination["users"][0]["id"], str)
                                 and bool(destination["users"][0]["id"]))
        except (KeyError, IndexError, TypeError):
            valid_destination = False
        if not valid_destination:
            raise StateError("persistent state contains an invalid outbound")
        sources = item.get("sources")
        try:
            content_hash = outbound_hash(item["outbound"])
        except (TypeError, ValueError, RecursionError) as e:
            raise StateError("persistent state contains an invalid outbound") from e
        if (not isinstance(key, str) or len(key) != 64 or content_hash != key
                or not isinstance(sources, list) or not sources
                or any(not isinstance(source, str) or len(source) != 64 for source in sources)):
            raise StateError("persistent state contains an invalid outbound or subscription reference")
        for metric in ("latency_ms", "last_latency_ms", "download_mbps"):
            value = item.get(metric)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                      or not math.isfinite(value) or value < 0):
                raise StateError("persistent state contains invalid measurements")
        if item.get("latency_ms") is not None and item.get("last_latency_ms") is None:
            item["last_latency_ms"] = item["latency_ms"]
        if not isinstance(item.get("active", False), bool):
            raise StateError("persistent state contains invalid active status")
    return state


def save_state(path, state):
    path = Path(path)
    name = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(state, output, indent=2, ensure_ascii=False, allow_nan=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        name = None
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except (OSError, ValueError, TypeError) as e:
        raise StateError("cannot save persistent state") from e
    finally:
        if name is not None:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass


@contextmanager
def state_lock(path):
    path = Path(path)
    lock_path = path.with_name(path.name + ".lock")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as e:
        raise StateError("cannot lock persistent state") from e
    with os.fdopen(fd, "a+") as lock:
        try:
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise StateError("another updater is already using this state file") from e
        except OSError as e:
            raise StateError("cannot lock persistent state") from e
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)

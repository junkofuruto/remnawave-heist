#!/usr/bin/env python3

import base64, json, os, re, secrets, sys, urllib.parse, urllib.request, urllib.error, ssl
from pathlib import Path
from datetime import datetime

ENV_FILE = Path(os.environ.get("REMNAWAVE_ENV_FILE", Path(__file__).with_name(".env")))
TAG_PREFIX = "out-auto-"
FIXED_TAGS = ("direct", "block")
MAX_OUTBOUNDS = 20
BACKUP_DIR = "./backups"
DRY_RUN = "--dry-run" in sys.argv

SSL_CTX = ssl.create_default_context(cafile="./certificate.pem")
SSL_CTX.verify_flags &= ~ssl.VERIFY_X509_STRICT

def load_env_file(path: Path) -> None:
    if not path.is_file():
        sys.exit(f"env file not found: {path}")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)

load_env_file(ENV_FILE)

PANEL_URL = os.environ["REMNAWAVE_URL"].rstrip("/")
PANEL_TOKEN = os.environ["REMNAWAVE_TOKEN"]
PROFILE_UUID = os.environ["REMNAWAVE_PROFILE_UUID"]
SUB_URL = os.environ["SUB_URL"]

def panel(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        PANEL_URL + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {PANEL_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=SSL_CTX) as r:
            payload = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} failed: {e.code} {e.read().decode()[:300]}")
    return payload.get("response", payload)


def fetch_subscription(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read().decode("utf-8", "ignore")
    if "vless://" not in text:
        try:
            text = base64.b64decode(text.strip() + "==").decode("utf-8", "ignore")
        except Exception:
            pass
    links, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("vless://") and line not in seen:
            seen.add(line)
            links.append(line)
    return links


def link_to_outbound(link, tag):
    u = urllib.parse.urlsplit(link)
    q = dict(urllib.parse.parse_qsl(u.query))
    net = q.get("type", "tcp")
    if net == "raw":
        net = "tcp"
    stream = {"network": net}

    sec = q.get("security", "none")
    if sec == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": q.get("sni", ""),
            "fingerprint": q.get("fp", "chrome"),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", "/"),
        }
    elif sec == "tls":
        stream["security"] = "tls"
        tls = {"serverName": q.get("sni", u.hostname)}
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        stream["tlsSettings"] = tls

    if net == "ws":
        stream["wsSettings"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", "")}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}

    user = {"id": u.username, "encryption": "none"}
    if q.get("flow"):
        user["flow"] = q["flow"]

    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{"address": u.hostname, "port": u.port or 443, "users": [user]}]},
        "streamSettings": stream,
    }


def main():
    links = fetch_subscription(SUB_URL)[:MAX_OUTBOUNDS]
    if not links:
        sys.exit("no vless links in subscription, profile not changed")

    run_id = secrets.token_hex(4)
    new_outbounds = []
    for i, link in enumerate(links, 1):
        name = urllib.parse.unquote(urllib.parse.urlsplit(link).fragment) or "node"
        slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")[:20] or "node"
        tag = f"{TAG_PREFIX}{run_id}-{i:02d}-{slug}"
        try:
            new_outbounds.append(link_to_outbound(link, tag))
        except Exception as e:
            print(f"skip link {i}: {e}", file=sys.stderr)
    if not new_outbounds:
        sys.exit("no outbounds could be parsed, profile not changed")

    profile = panel("GET", f"/api/config-profiles/{PROFILE_UUID}")
    cfg = profile.get("config", profile)
    if isinstance(cfg, str):
        cfg = json.loads(cfg)

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup = os.path.join(BACKUP_DIR, f"{PROFILE_UUID}-{datetime.now():%Y%m%d-%H%M%S}.json")
    with open(backup, "w") as f:
        json.dump(profile, f, indent=2)

    existing = cfg.get("outbounds", [])
    fixed = [o for o in existing if o.get("tag") in FIXED_TAGS]
    missing = set(FIXED_TAGS) - {o.get("tag") for o in fixed}
    if missing:
        print(f"warning: profile has no outbound(s) {sorted(missing)}", file=sys.stderr)
    others = [
        o for o in existing
        if o.get("tag") not in FIXED_TAGS and not str(o.get("tag", "")).startswith(TAG_PREFIX)
    ]
    cfg["outbounds"] = fixed + others + new_outbounds

    print(f"removing old {TAG_PREFIX}* outbounds, adding {len(new_outbounds)} new")
    print(f"backup saved to {backup}")
    if DRY_RUN:
        print(json.dumps(new_outbounds[:2], indent=2))
        return

    panel("PATCH", "/api/config-profiles", {"uuid": PROFILE_UUID, "config": cfg})
    print("profile updated")


if __name__ == "__main__":
    main()

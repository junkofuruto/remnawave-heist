import base64
import urllib.error
import urllib.parse
import urllib.request


from downloads import download_opener


def fetch_subscription(url, opener=None):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with (opener or download_opener()).open(req, timeout=30) as r:
            text = r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as error:
        error.close()
        raise
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

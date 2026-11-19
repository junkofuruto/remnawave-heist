import base64
import json
import urllib.request
import urllib.error
import urllib.parse

from downloads import download_opener


def decode_base64(text):
    text = text.strip()
    text += "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text).decode("utf-8", "ignore")

def fetch_subscription(url, opener=None):
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0"}
    )

    try:
        with (opener or download_opener()).open(req, timeout=30) as r:
            text = r.read().decode("utf-8", "ignore").strip()
    except urllib.error.HTTPError as error:
        error.close()
        raise

    # Decode Base64 subscription if necessary.
    if not any(
        p in text for p in (
            "vless://", "vmess://", "trojan://",
            "ss://", "socks://", "http://"
        )
    ):
        try:
            decoded = decode_base64(text)
            if "://" in decoded:
                text = decoded
        except Exception:
            pass

    links = []
    seen = set()

    supported = (
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
    )

    for line in text.splitlines():
        line = line.strip()

        # Support multiple links separated by whitespace.
        for item in line.split():
            if item.startswith(supported) and item not in seen:
                seen.add(item)
                links.append(item)

    return links


def ss_to_outbound(link, tag):
    """Parse a Shadowsocks URI into an outbound configuration.

    Supports both:
      ss://method:password@host:port#tag        (plaintext)
      ss://base64(method:password@host:port)#tag  (base64-encoded)
    """
    if link.startswith("ss://"):
        link = link[5:]

    if "#" in link:
        link, fragment = link.rsplit("#", 1)
    else:
        fragment = ""

    def parse_userinfo_hostport(text):
        """Parse method:password@host:port from decoded text."""
        if "@" not in text:
            raise ValueError("missing @ separator in SS URI")
        userinfo, host_port = text.rsplit("@", 1)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            method = userinfo
            password = ""
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"invalid port: {port_str}")
        else:
            host = host_port
            port = 443
        if not host:
            raise ValueError("missing server address")
        if not password:
            raise ValueError("missing password")
        return host, port, method, password

    # Try base64 decode first (standard ss:// format)
    decoded = None
    try:
        decoded = base64.b64decode(link + "==").decode("utf-8", "ignore")
        # Verify the decoded text looks like method:password@host:port
        if "@" in decoded and ":" in decoded.split("@", 1)[0]:
            host, port, method, password = parse_userinfo_hostport(decoded)
        else:
            decoded = None
    except Exception:
        decoded = None

    if decoded is None:
        # Try parsing directly as method:password@host:port
        host, port, method, password = parse_userinfo_hostport(link)

    return {
        "tag": tag,
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
                "level": 0,
                "email": ""
            }]
        },
        "streamSettings": {"network": "tcp", "security": "none"},
    }


def link_to_outbound(link, tag):
    scheme = urllib.parse.urlsplit(link).scheme.lower()

    if scheme == "vless":
        return vless_to_outbound(link, tag)

    if scheme == "vmess":
        return vmess_to_outbound(link, tag)

    if scheme == "ss":
        return ss_to_outbound(link, tag)

    if scheme == "trojan":
        return trojan_to_outbound(link, tag)

    raise ValueError(f"Unsupported protocol: {scheme}")


def vless_to_outbound(link, tag):
    u = urllib.parse.urlsplit(link)
    q = dict(urllib.parse.parse_qsl(u.query))

    net = q.get("type", "tcp")
    if net == "raw":
        net = "tcp"

    stream = {"network": net}

    sec = q.get("security", "none")
    if sec == "none":
        stream["security"] = "none"

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
        stream["wsSettings"] = {
            "path": q.get("path", "/"),
            "headers": {"Host": q.get("host", "")},
        }

    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": q.get("serviceName", ""),
        }

    user = {
        "id": urllib.parse.unquote(u.username or ""),
        "encryption": "none",
    }

    if q.get("flow"):
        user["flow"] = q["flow"]

    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": u.hostname,
                "port": u.port or 443,
                "users": [user],
            }]
        },
        "streamSettings": stream,
    }


def vmess_to_outbound(link, tag):
    raw = link[len("vmess://"):].split("#", 1)[0]
    data = json.loads(decode_base64(raw))

    net = data.get("net", "tcp")
    if net == "raw":
        net = "tcp"

    stream = {"network": net}

    if data.get("tls") == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": data.get("sni") or data.get("host", ""),
            "allowInsecure": data.get("allowInsecure") == "1",
        }

        if data.get("alpn"):
            stream["tlsSettings"]["alpn"] = data["alpn"].split(",")
    else:
        stream["security"] = "none"

    if net == "ws":
        stream["wsSettings"] = {
            "path": data.get("path", "/"),
            "headers": {"Host": data.get("host", "")},
        }

    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": data.get("path", ""),
        }

    return {
        "tag": tag,
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": data["add"],
                "port": int(data["port"]),
                "users": [{
                    "id": data["id"],
                    "alterId": int(data.get("aid", 0)),
                    "security": data.get("scy", "auto"),
                }],
            }]
        },
        "streamSettings": stream,
    }


def trojan_to_outbound(link, tag):
    u = urllib.parse.urlsplit(link)
    q = dict(urllib.parse.parse_qsl(u.query))

    net = q.get("type", "tcp")
    if net == "raw":
        net = "tcp"

    stream = {
        "network": net,
        "security": "tls",
        "tlsSettings": {
            "serverName": q.get("sni", u.hostname),
        },
    }

    if q.get("alpn"):
        stream["tlsSettings"]["alpn"] = q["alpn"].split(",")

    if net == "ws":
        stream["wsSettings"] = {
            "path": q.get("path", "/"),
            "headers": {"Host": q.get("host", "")},
        }

    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": q.get("serviceName", ""),
        }

    return {
        "tag": tag,
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": u.hostname,
                "port": u.port or 443,
                "password": urllib.parse.unquote(u.username or ""),
            }]
        },
        "streamSettings": stream,
    }


def shadowsocks_to_outbound(link, tag):
    u = urllib.parse.urlsplit(link)

    userinfo = u.username or ""
    host = u.hostname
    port = u.port

    if not host:
        raw = link[len("ss://"):].split("#", 1)[0]
        raw = raw.split("?", 1)[0]

        decoded = decode_base64(urllib.parse.unquote(raw))
        auth, hostport = decoded.rsplit("@", 1)

        method, password = auth.split(":", 1)
        parsed = urllib.parse.urlsplit("//" + hostport)

        host = parsed.hostname
        port = parsed.port

    else:
        if u.password is not None:
            auth = userinfo + ":" + u.password
        else:
            auth = decode_base64(userinfo)

        method, password = auth.split(":", 1)

    if not host or not port:
        raise ValueError("Invalid Shadowsocks server address")

    return {
        "tag": tag,
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": urllib.parse.unquote(password),
            }]
        },
        "streamSettings": {"network": "tcp", "security": "none"},
    }


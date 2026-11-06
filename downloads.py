import base64
import http.client
import ipaddress
import socket
import struct
import urllib.parse
import urllib.request


class SocksProxyError(OSError):
    pass


def _receive_exact(sock, length):
    parts = bytearray()
    while len(parts) < length:
        chunk = sock.recv(length - len(parts))
        if not chunk:
            raise SocksProxyError("SOCKS5 proxy closed the connection")
        parts.extend(chunk)
    return bytes(parts)


def _socks5_connect(proxy, host, port, timeout, source_address=None):
    parsed = urllib.parse.urlsplit(proxy)
    username = urllib.parse.unquote(parsed.username).encode("utf-8") if parsed.username is not None else None
    password = urllib.parse.unquote(parsed.password or "").encode("utf-8")
    if username is not None and (not 1 <= len(username) <= 255 or not 1 <= len(password) <= 255):
        raise SocksProxyError("SOCKS5 username and password must each be 1-255 bytes")
    sock = socket.create_connection((parsed.hostname, parsed.port), timeout, source_address)
    try:
        method = 2 if username is not None else 0
        sock.sendall(bytes((5, 1, method)))
        selection = _receive_exact(sock, 2)
        if selection[0] != 5:
            raise SocksProxyError("proxy did not respond as SOCKS5; check the configured proxy scheme")
        if selection[1] != method:
            raise SocksProxyError("SOCKS5 proxy rejected the configured authentication method")
        if username is not None:
            sock.sendall(bytes((1, len(username))) + username + bytes((len(password),)) + password)
            if _receive_exact(sock, 2) != b"\x01\x00":
                raise SocksProxyError("SOCKS5 proxy authentication failed")

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if parsed.scheme == "socks5h":
                name = host.encode("idna")
                if not 1 <= len(name) <= 255:
                    raise SocksProxyError("invalid SOCKS5 destination hostname")
                target = b"\x03" + bytes((len(name),)) + name
            else:
                records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                if not records:
                    raise SocksProxyError("SOCKS5 destination could not be resolved")
                address = ipaddress.ip_address(records[0][4][0])
                target = bytes((1 if address.version == 4 else 4,)) + address.packed
        else:
            target = bytes((1 if address.version == 4 else 4,)) + address.packed
        sock.sendall(b"\x05\x01\x00" + target + struct.pack("!H", port))
        version, status, reserved, atyp = _receive_exact(sock, 4)
        if version != 5 or reserved != 0:
            raise SocksProxyError("invalid SOCKS5 proxy response")
        if status:
            reasons = {
                1: "general failure", 2: "connection forbidden", 3: "network unreachable",
                4: "host unreachable", 5: "connection refused", 6: "connection timed out",
                7: "command unsupported", 8: "address type unsupported",
            }
            raise SocksProxyError(f"SOCKS5 proxy connection failed: {reasons.get(status, 'unknown error')}")
        if atyp == 1:
            length = 4
        elif atyp == 4:
            length = 16
        elif atyp == 3:
            length = _receive_exact(sock, 1)[0]
        else:
            raise SocksProxyError("invalid SOCKS5 proxy response")
        _receive_exact(sock, length + 2)
        return sock
    except BaseException:
        sock.close()
        raise


class SocksHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, proxy, **kwargs):
        self.proxy = proxy
        super().__init__(host, **kwargs)

    def connect(self):
        self.sock = _socks5_connect(self.proxy, self.host, self.port, self.timeout, self.source_address)


class SocksHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, proxy, **kwargs):
        self.proxy = proxy
        super().__init__(host, **kwargs)

    def connect(self):
        sock = _socks5_connect(self.proxy, self.host, self.port, self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class SocksHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, proxy):
        super().__init__()
        self.proxy = proxy

    def http_open(self, request):
        return self.do_open(lambda host, **kwargs: SocksHTTPConnection(host, self.proxy, **kwargs), request)


class SocksHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, proxy):
        super().__init__()
        self.proxy = proxy

    def https_open(self, request):
        return self.do_open(lambda host, **kwargs: SocksHTTPSConnection(host, self.proxy, **kwargs),
                            request, context=self._context)



class ExplicitProxyHandler(urllib.request.ProxyHandler):
    """Use the configured HTTP proxy even when system NO_PROXY is set."""

    def proxy_open(self, request, proxy, protocol):
        parsed = urllib.parse.urlsplit(proxy)
        if parsed.username is not None:
            credentials = "{}:{}".format(
                urllib.parse.unquote(parsed.username), urllib.parse.unquote(parsed.password or "")
            )
            encoded = base64.b64encode(credentials.encode()).decode("ascii")
            request.add_header("Proxy-authorization", "Basic " + encoded)
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        request.set_proxy(f"{host}:{parsed.port}", "http")
        return None


def download_opener(proxy=None):
    if proxy is None:
        return urllib.request.build_opener()
    if urllib.parse.urlsplit(proxy).scheme in ("socks5", "socks5h"):
        return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                           SocksHTTPHandler(proxy), SocksHTTPSHandler(proxy))
    return urllib.request.build_opener(ExplicitProxyHandler({"http": proxy, "https": proxy}))

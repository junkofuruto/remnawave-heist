import copy
import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger("remnawave.api")

class ProfileConflictError(Exception):
    pass


class RemnawaveAPI:
    def __init__(self, url, token, ssl_ctx=None):
        self.url = url.rstrip("/")
        self.token = token
        self.ssl_ctx = ssl_ctx
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl_ctx)
        )

    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with self.opener.open(req, timeout=30) as r:
                payload = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            logger.error("Panel request failed: HTTP %s (%s)", e.code, method)
            e.close()
            raise SystemExit(1) from None
        except (urllib.error.URLError, OSError):
            logger.error("Could not reach panel (%s request)", method)
            raise SystemExit(1) from None
        except (UnicodeError, json.JSONDecodeError):
            logger.error("Panel returned an invalid JSON response (%s request)", method)
            raise SystemExit(1) from None
        return payload.get("response", payload)

    def get_profile(self, profile_uuid):
        return self.request("GET", f"/api/config-profiles/{profile_uuid}")

    def update_outbounds(self, profile_uuid, expected_outbounds, new_outbounds):
        profile = self.get_profile(profile_uuid)
        latest = profile.get("config", profile)
        if isinstance(latest, str):
            latest = json.loads(latest)
        if latest.get("outbounds", []) != expected_outbounds:
            raise ProfileConflictError("profile outbounds changed since the previous update")
        updated = copy.deepcopy(latest)
        updated["outbounds"] = copy.deepcopy(new_outbounds)
        self.update_profile(profile_uuid, updated)

    def update_profile(self, profile_uuid, config):
        return self.request("PATCH", "/api/config-profiles", {"uuid": profile_uuid, "config": config})

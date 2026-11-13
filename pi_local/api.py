"""Small Pi-hole v6 API client.

Documented calls used here, from the FTL API table and FTL's API tests:

- POST /api/auth with a JSON password, then the ``sid`` header
- DELETE /api/auth to end that session
- GET /api/stats/database/summary?from=&until= for a historical range
- GET /api/stats/summary only to read ``gravity`` point-in-time facts
- GET /api/info/version
- GET /api/dns/blocking
- GET /api/lists

Top domains, clients, and the query log are not requested.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from pi_local.redact import error_key, redact
from pi_local.urls import validate_base_url

RETRY_STATUSES = frozenset({429, 502, 503, 504})
MAX_ATTEMPTS = 3


@dataclass
class ApiResult:
    status: int | None
    payload: object
    error_key: str | None = None
    unavailable: bool = False


@dataclass
class PiHoleClient:
    base_url: str
    ca_file: str | None = None
    transport: object | None = None
    sleeper: object = time.sleep
    max_attempts: int = MAX_ATTEMPTS
    sid: str | None = None
    _secrets: list[str] = field(default_factory=list)
    calls: list[tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.base_url = validate_base_url(self.base_url)
        if self.transport is None:
            self.transport = UrllibTransport(self.base_url, self.ca_file)

    def login(self, password: str) -> None:
        self._secrets.append(password)
        try:
            result = self._request("POST", "/api/auth", {"password": password}, auth=False)
        finally:
            self._forget(password)
        session = result.payload.get("session") if isinstance(result.payload, dict) else None
        sid = session.get("sid") if isinstance(session, dict) else None
        valid = session.get("valid") if isinstance(session, dict) else None
        if result.unavailable or not isinstance(sid, str) or not sid or valid is not True:
            raise ApiUnavailable("authentication failed", result.error_key)
        self.sid = sid
        self._secrets.append(sid)

    def logout(self) -> None:
        try:
            if self.sid:
                self._request("DELETE", "/api/auth", None, auth=True, retry=False)
        finally:
            self._forget(self.sid)
            self.sid = None

    def get_json(self, path: str) -> ApiResult:
        return self._request("GET", path, None, auth=True)

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None,
        *,
        auth: bool,
        retry: bool = True,
    ) -> ApiResult:
        attempts = self.max_attempts if retry else 1
        last_key = None
        for attempt in range(1, attempts + 1):
            self.calls.append((method, path.split("?", 1)[0]))
            headers = {"Accept": "application/json"}
            if auth and self.sid:
                headers["sid"] = self.sid
            try:
                status, raw = self.transport.request(method, path, body, headers)
            except TransportError as exc:
                last_key = "transport"
                if attempt == attempts:
                    return ApiResult(None, None, last_key, unavailable=True)
                self.sleeper(attempt)
                continue
            if 300 <= status < 400:
                return ApiResult(status, None, "redirect-refused", unavailable=True)
            if status == 409:
                return ApiResult(status, None, "not-acknowledged", unavailable=True)
            payload = _decode(raw)
            key = error_key(payload)
            if status == 200 and key is None:
                return ApiResult(status, payload, None, unavailable=False)
            last_key = key or f"http_{status}"
            if status not in RETRY_STATUSES or attempt == attempts:
                return ApiResult(status, None, last_key, unavailable=True)
            self.sleeper(attempt)
        return ApiResult(None, None, last_key, unavailable=True)

    def _forget(self, secret: str | None) -> None:
        if secret and secret in self._secrets:
            self._secrets.remove(secret)

    def redact(self, text: str) -> str:
        return redact(text, list(self._secrets))


class ApiUnavailable(Exception):
    def __init__(self, message: str, error_key_name: str | None = None) -> None:
        super().__init__(message)
        self.error_key = error_key_name


class TransportError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    def __init__(self, base_url: str, ca_file: str | None) -> None:
        self.base_url = base_url
        context = ssl.create_default_context(cafile=ca_file)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPHandler(),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def request(self, method: str, path: str, body: dict | None, headers: dict) -> tuple[int, bytes]:
        data = None
        send_headers = dict(headers)
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            send_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=send_headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                return exc.code, b""
            return exc.code, exc.read()
        except urllib.error.URLError as exc:
            raise TransportError("request failed") from exc


def _decode(raw: bytes) -> object:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None

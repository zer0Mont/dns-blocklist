"""Remove secrets from anything that might be logged."""

from __future__ import annotations

import re

_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
_PASSWORD_FIELD = re.compile(
    r"(?i)(\"password\"\s*:\s*\")([^\"]*)(\")"
)
_SID_FIELD = re.compile(r"(?i)(\"sid\"\s*:\s*\")([^\"]*)(\")")


def redact(text: str, secrets: list[str] | None = None) -> str:
    cleaned = text
    for secret in secrets or []:
        if secret:
            cleaned = cleaned.replace(secret, "[redacted]")
    cleaned = _BEARER.sub("Bearer [redacted]", cleaned)
    cleaned = _PASSWORD_FIELD.sub(r"\1[redacted]\3", cleaned)
    cleaned = _SID_FIELD.sub(r"\1[redacted]\3", cleaned)
    return cleaned


def error_key(payload: object) -> str | None:
    """Return a short API error key, never the error body."""
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if not isinstance(error, dict):
        return None
    key = error.get("key")
    if isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key):
        return key
    return None

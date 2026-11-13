"""URL rules for the Pi-hole API and subscribed list addresses."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def validate_base_url(url: str) -> str:
    """Allow verified HTTPS, or HTTP only when the host is loopback.

    Loopback HTTP never leaves the machine, so there is no network path to
    protect. A LAN or public host, including a private address such as the
    Pi-hole on the home network, must use HTTPS. Certificate checks stay on.
    There is no option to skip verification.
    """
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if parts.username or parts.password:
        raise ValueError("credentials must not be embedded in the URL")
    if parts.scheme == "http":
        if host not in LOOPBACK_HOSTS:
            raise ValueError(
                "HTTP is only allowed for loopback; a remote Pi-hole requires verified HTTPS"
            )
        return _without_trailing_slash(parts)
    if parts.scheme != "https":
        raise ValueError("unsupported URL scheme")
    if not host:
        raise ValueError("URL is missing a host")
    return _without_trailing_slash(parts)


def normalize_list_url(url: str) -> str:
    """Compare list addresses without caring about scheme/host case or a trailing slash."""
    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("list address is not an http(s) URL")
    port = f":{parts.port}" if parts.port else ""
    netloc = parts.hostname.lower() + port
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def _without_trailing_slash(parts) -> str:
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, parts.query, ""))

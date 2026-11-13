"""Build a calendar-day aggregate from validated Pi-hole responses.

``GET /api/stats/summary`` is the live dashboard total. It is not the previous
civil day, so its query counters are never copied into this record. Historical
counts come only from ``GET /api/stats/database/summary``.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from pi_local.api import PiHoleClient
from pi_local.window import UNTIL_SEMANTICS, previous_london_day

SCHEMA = "pihole-daily-aggregate/1"
# Fields copied from health endpoints. Anything else, including uptime, is dropped.
BLOCKING_ALLOW = ("blocking", "timer")
GRAVITY_ALLOW = ("domains_being_blocked", "last_update", "last_update_status")


def unavailable(source: str, reason: str) -> dict:
    return {"status": "unavailable", "source": source, "reason": reason}


def extract_database_summary(payload: object) -> dict:
    """Require the keys FTL's API test lists, then drop client data.

    A validated ``sum_queries`` of 0 is a real zero, not an unavailable read.
    The percentage is omitted when the denominator is 0.
    """
    source = "GET /api/stats/database/summary"
    if not isinstance(payload, dict):
        return unavailable(source, "response was not a JSON object")
    required = ("sum_queries", "sum_blocked", "percent_blocked", "total_clients")
    if any(key not in payload for key in required):
        return unavailable(source, "database summary schema did not match")
    total = payload["sum_queries"]
    blocked = payload["sum_blocked"]
    if _bad_count(total) or _bad_count(blocked) or blocked > total:
        return unavailable(source, "sum_queries and sum_blocked were inconsistent")
    if _bad_count(payload["total_clients"]):
        return unavailable(source, "database summary schema did not match")
    reported = payload["percent_blocked"]
    percent = None
    if total == 0:
        if reported not in (0, 0.0, None):
            return unavailable(source, "percent_blocked did not match a zero day")
    else:
        if isinstance(reported, bool) or not isinstance(reported, (int, float)):
            return unavailable(source, "percent_blocked was not a number")
        percent = round(100.0 * blocked / total, 3)
        if abs(float(reported) - percent) > 0.05:
            return unavailable(source, "percent_blocked did not match the counts")
    return {
        "status": "ok",
        "source": source,
        "total": total,
        "blocked": blocked,
        "percent_blocked": percent,
    }


def extract_gravity(payload: object) -> dict:
    source = "GET /api/stats/summary gravity"
    if not isinstance(payload, dict) or not isinstance(payload.get("gravity"), dict):
        return unavailable(source, "gravity object was not present")
    gravity = payload["gravity"]
    domains = gravity.get("domains_being_blocked")
    if _bad_count(domains):
        return unavailable(source, "domains_being_blocked was missing or not a count")
    last_update = gravity.get("last_update", None)
    if "last_update" not in gravity:
        last_update_value = None
        last_update_status = "unsupported"
    elif last_update is None or (isinstance(last_update, int) and not isinstance(last_update, bool) and last_update >= 0):
        last_update_value = last_update
        last_update_status = "ok"
    else:
        last_update_value = None
        last_update_status = "invalid"
    return {
        "status": "ok",
        "source": source,
        "domains_being_blocked": domains,
        "last_update": last_update_value,
        "last_update_status": last_update_status,
    }


def extract_version(payload: object) -> dict:
    source = "GET /api/info/version"
    version = _dig(payload, "version", "ftl", "local", "version")
    if not isinstance(version, str) or not version:
        return unavailable(source, "version.ftl.local.version was not a string")
    return {"status": "ok", "source": source, "ftl": version}


def extract_blocking(payload: object) -> dict:
    source = "GET /api/dns/blocking"
    if not isinstance(payload, dict) or payload.get("blocking") not in {"enabled", "disabled"}:
        return unavailable(source, "blocking was not enabled or disabled")
    timer = payload.get("timer")
    if timer is not None and _bad_count(timer):
        return unavailable(source, "timer was not null or a count")
    return {
        "status": "ok",
        "source": source,
        "blocking": payload["blocking"],
        "timer": timer,
    }


def collect_record(
    client: PiHoleClient,
    now: datetime,
    until_semantics: str | None = None,
    record_id: str | None = None,
) -> dict:
    window = previous_london_day(now)
    semantics = until_semantics if until_semantics in UNTIL_SEMANTICS else None
    errors = []
    if semantics is None:
        queries = unavailable(
            "GET /api/stats/database/summary",
            "until-semantics-unverified",
        )
        errors.append({"endpoint": "/api/stats/database/summary", "error_key": "until-semantics-unverified"})
    else:
        query = urlencode({"from": window.api_from, "until": window.api_until(semantics)})
        queries = _section(
            client,
            "/api/stats/database/summary?" + query,
            extract_database_summary,
            errors,
        )
    gravity = _section(client, "/api/stats/summary", extract_gravity, errors)
    version = _section(client, "/api/info/version", extract_version, errors)
    blocking = _section(client, "/api/dns/blocking", extract_blocking, errors)
    return _record(window, now, queries, gravity, version, blocking, errors, semantics, False, record_id)


def unavailable_record(now: datetime, reason: str) -> dict:
    window = previous_london_day(now)
    reason_name = reason or "authentication-failed"
    return _record(
        window,
        now,
        unavailable("GET /api/stats/database/summary", reason_name),
        unavailable("GET /api/stats/summary gravity", reason_name),
        unavailable("GET /api/info/version", reason_name),
        unavailable("GET /api/dns/blocking", reason_name),
        [{"endpoint": "/api/auth", "error_key": reason_name}],
        None,
        False,
        None,
    )


def synthetic_record(now: datetime) -> dict:
    window = previous_london_day(now)
    queries = {
        "status": "ok",
        "source": "synthetic",
        "total": 8,
        "blocked": 2,
        "percent_blocked": 25.0,
    }
    return _record(
        window,
        now,
        queries,
        unavailable("GET /api/stats/summary gravity", "synthetic dry-run"),
        unavailable("GET /api/info/version", "synthetic dry-run"),
        unavailable("GET /api/dns/blocking", "synthetic dry-run"),
        [],
        None,
        True,
        None,
    )


def _record(window, now, queries, gravity, version, blocking, errors, semantics, synthetic, record_id) -> dict:
    return {
        "schema": SCHEMA,
        "record_id": record_id or str(uuid.uuid4()),
        "synthetic": synthetic,
        "timezone": window.timezone,
        "collected_at": now.astimezone(timezone.utc).isoformat(),
        "interval": window.as_dict(semantics),
        "queries": queries,
        "gravity": {key: gravity[key] for key in ("status", "source", "reason", *GRAVITY_ALLOW) if key in gravity},
        "version": {key: version[key] for key in ("status", "source", "reason", "ftl") if key in version},
        "blocking": {key: blocking[key] for key in ("status", "source", "reason", *BLOCKING_ALLOW) if key in blocking},
        "completeness": {
            "queries": "validated" if queries.get("status") == "ok" else "unavailable",
            "version": "validated" if version.get("status") == "ok" else "unavailable",
            "blocking": "validated" if blocking.get("status") == "ok" else "unavailable",
            "gravity": "validated" if gravity.get("status") == "ok" else "unavailable",
            "day_coverage": "not-evidenced",
        },
        "errors": errors,
    }


def write_private_json(path: Path, payload: dict) -> None:
    parent_existed = path.parent.exists()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not parent_existed:
        os.chmod(path.parent, 0o700)
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, encoded)
    finally:
        os.close(descriptor)


def _section(client: PiHoleClient, path: str, extractor, errors: list) -> dict:
    result = client.get_json(path)
    if result.unavailable:
        errors.append({"endpoint": path.split("?", 1)[0], "error_key": result.error_key})
        return unavailable(path.split("?", 1)[0], result.error_key or "unavailable")
    parsed = extractor(result.payload)
    if parsed.get("status") != "ok":
        errors.append({"endpoint": path.split("?", 1)[0], "error_key": "invalid_schema"})
    return parsed


def _bad_count(value: object) -> bool:
    return isinstance(value, bool) or not isinstance(value, int) or value < 0


def _dig(payload: object, *keys: str) -> object:
    current = payload
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current

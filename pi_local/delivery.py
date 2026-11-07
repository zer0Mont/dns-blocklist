"""Delivery stays off until a private receiver contract is approved.

Prepare-only mode does not open a socket and does not write a queue.
HTTP 409 is not success. Redirects are not followed, because that would send
the bearer token to another host. Cursor's routine help describes POST JSON
with Authorization Bearer and treats HTTP 200 as accepted, not finished.
It does not define the body fields, acknowledgement, or 409 handling, so
those stay unresolved until the operator approves a contract.
"""

from __future__ import annotations

DOCUMENTED_CONTRACT = "cursor-routine-webhook-bearer-json"
DOCUMENTATION = "https://cursor.com/help/grok-bot/routines"
MAX_ATTEMPTS = 3
MAX_QUEUED = 0
RETAIN_DAYS = 7
REDIRECTS = frozenset({301, 302, 303, 307, 308})
RETRY_STATUSES = frozenset({429, 502, 503, 504})


def delivery_request(config: dict, payload: dict, key: str | None) -> dict:
    delivery = config.get("delivery") if isinstance(config, dict) else None
    if not isinstance(delivery, dict) or delivery.get("enabled") is not True:
        return _idle("disabled")
    if delivery.get("prepare_only", True) is not False:
        return _idle("prepare-only")
    if delivery.get("contract_approved") is not True or delivery.get("contract") != DOCUMENTED_CONTRACT:
        return _idle("unresolved-contract")
    return _idle("not-wired-until-approval")


def classify_http(status: int) -> str:
    if status in REDIRECTS:
        return "redirect-refused"
    if status == 409:
        return "not-acknowledged"
    if status == 200:
        return "accepted"
    if status in RETRY_STATUSES:
        return "retry"
    return "failed"


def plan_attempts(statuses: list[int], max_attempts: int = MAX_ATTEMPTS) -> list[str]:
    """Same record id is reused. Stop on accept, redirect, 409, or a hard failure."""
    if max_attempts < 1:
        raise ValueError("attempts must be bounded")
    outcomes = []
    for status in statuses[:max_attempts]:
        kind = classify_http(status)
        outcomes.append(kind)
        if kind != "retry":
            break
    return outcomes


def attempt_silence(config: dict, payload: dict, key: str | None, transport=None) -> dict:
    """Prepare-only delivery does not call the network and does not queue."""
    decision = delivery_request(config, payload, key)
    if decision.get("network") or decision.get("queued") or decision.get("delivered"):
        raise RuntimeError("prepare-only delivery tried to leave the machine")
    enqueue(None, payload, config.get("delivery") or {})
    return decision


def enqueue(directory, payload: dict, policy: dict) -> dict:
    """Prepare-only and unapproved delivery never queue."""
    if policy.get("prepare_only", True) is not False or policy.get("enabled") is not True:
        return {"queued": False, "reason": "prepare-only", "retention_days": RETAIN_DAYS, "max_queued": MAX_QUEUED}
    if policy.get("contract_approved") is not True:
        return {"queued": False, "reason": "unresolved-contract", "retention_days": RETAIN_DAYS, "max_queued": MAX_QUEUED}
    return {"queued": False, "reason": "queue-disabled", "retention_days": RETAIN_DAYS, "max_queued": MAX_QUEUED}


def _idle(reason: str) -> dict:
    return {
        "delivered": False,
        "network": False,
        "queued": False,
        "reason": reason,
        "documentation": DOCUMENTATION,
    }

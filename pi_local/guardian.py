"""Read-only check that one subscribed URL is a block list.

Pi-hole's lists API returns ``type`` ``block`` or ``allow``. In the gravity
database those are ``adlist.type`` 0 (block / gravity) and 1 (allow /
antigravity). This module only classifies API records. It does not open the
database and it has no add, delete, or type-change operation.

Row ids are reported when the API provides them. No id is treated as special.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pi_local.urls import normalize_list_url

BLOCK_TYPES = frozenset({"block", 0, "0"})
ALLOW_TYPES = frozenset({"allow", "antigravity", 1, "1"})


@dataclass(frozen=True)
class ListMatch:
    id: object
    address: str
    api_type: object
    kind: str
    enabled: object

    def public_dict(self) -> dict:
        return {
            "id": self.id,
            "address": self.address,
            "api_type": self.api_type,
            "kind": self.kind,
            "enabled": self.enabled,
            "db_type": {"block": 0, "allow": 1}.get(self.kind),
        }


@dataclass
class GuardianCheck:
    ok: bool
    matches: list[ListMatch] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    @property
    def action(self) -> str:
        return "report-only"


def classify_list_type(value: object) -> str | None:
    if value in BLOCK_TYPES:
        return "block"
    if value in ALLOW_TYPES:
        return "allow"
    return None


def parse_lists(payload: object) -> list[dict]:
    if not isinstance(payload, dict) or not isinstance(payload.get("lists"), list):
        raise ValueError("lists payload is missing the lists array")
    parsed = []
    for item in payload["lists"]:
        if not isinstance(item, dict) or "address" not in item or "type" not in item:
            raise ValueError("a list entry is missing address or type")
        if not isinstance(item["address"], str):
            raise ValueError("a list address is not a string")
        parsed.append(
            {
                "id": item.get("id"),
                "address": item["address"],
                "type": item["type"],
                "enabled": item.get("enabled"),
            }
        )
    return parsed


def check_guardian(entries: list[dict], expected_url: str) -> GuardianCheck:
    """Fail closed when the URL is missing, duplicated, disabled, or an allow list.

    The returned action is always report-only. Callers must not delete or recreate
    the row.
    """
    expected = normalize_list_url(expected_url)
    matches: list[ListMatch] = []
    for entry in entries:
        try:
            address = normalize_list_url(entry["address"])
        except ValueError:
            continue
        if address != expected:
            continue
        kind = classify_list_type(entry.get("type")) or "unrecognized"
        matches.append(
            ListMatch(
                id=entry.get("id"),
                address=address,
                api_type=entry.get("type"),
                kind=kind,
                enabled=entry.get("enabled"),
            )
        )
    check = GuardianCheck(ok=False, matches=matches)
    if not matches:
        check.messages.append(
            "Guardian URL is not subscribed. This job will not create or re-add it."
        )
        return check
    allows = [item for item in matches if item.kind == "allow"]
    unknown = [item for item in matches if item.kind == "unrecognized"]
    blocks = [item for item in matches if item.kind == "block"]
    if allows:
        check.messages.append(
            "An allow/antigravity subscription exists for this URL "
            "(API type allow, database type 1). Not deleting it."
        )
    if unknown:
        check.messages.append("A subscription has an unrecognized type. Not modifying it.")
    if len(matches) != 1:
        check.messages.append(
            "This URL is subscribed more than once. Not deleting the duplicate."
        )
    if len(blocks) != 1 or allows or unknown:
        return check
    block = blocks[0]
    if block.enabled is not True:
        check.messages.append(
            "The block subscription is not enabled. Not enabling it automatically."
        )
        return check
    check.ok = True
    check.messages.append(
        "One enabled block subscription matches this URL (API type block, database type 0)."
    )
    return check

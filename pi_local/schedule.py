"""Plan a daily Gravity refresh without editing unknown cron jobs.

Pi-hole v6 still ships ``/etc/cron.d/pihole``. The stock template runs
``pihole updateGravity`` once a week and also flushes logs and runs the version
check. This module recognises only those command shapes. Anything else blocks
an edit. The daily command is ``pihole updateGravity`` with no list arguments.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

GRAVITY_ARGV = ("pihole", "updateGravity")
_FORBIDDEN = ("sqlite", "/api/lists", "type=allow", "type=block", "antigravity", "-up", "updatePihole")


@dataclass
class CronPlan:
    can_enable_gravity: bool
    can_edit_cron: bool
    gravity_lines: int
    unknown_lines: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    edited_text: str | None = None


def gravity_command() -> tuple[str, ...]:
    return GRAVITY_ARGV


def classify_cron_command(command: str) -> str:
    lowered = command.lower()
    if any(token in lowered for token in _FORBIDDEN):
        return "unknown"
    if re.search(r"(^|\s)pihole\s+updategravity(\s|$)", lowered):
        return "updateGravity"
    if re.search(r"(^|\s)pihole\s+-g(\s|$)", lowered):
        return "updateGravity"
    if re.search(r"(^|\s)pihole\s+flush(\s|$)", lowered):
        return "flush"
    if re.search(r"(^|\s)pihole\s+updatechecker(\s|$)", lowered):
        return "updatechecker"
    if "logrotate" in lowered and "pihole" in lowered:
        return "logrotate"
    return "unknown"


def _command_portion(line: str) -> str:
    return line.split(">", 1)[0].strip()


def inspect_cron(text: str) -> CronPlan:
    gravity = 0
    unknown: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        kind = classify_cron_command(_command_portion(stripped))
        if kind == "updateGravity":
            gravity += 1
        elif kind == "unknown":
            unknown.append(stripped)
    messages = []
    can_edit = not unknown and gravity <= 1
    can_enable = can_edit
    if unknown:
        messages.append("Cron contains an unrecognised command. It will not be edited.")
        can_enable = False
    if gravity > 1:
        messages.append("More than one updateGravity line was found. None will be changed.")
        can_enable = False
    if gravity == 1:
        messages.append(
            "A weekly updateGravity line is present. Enabling a daily run without "
            "commenting that line would update Gravity twice on that weekday."
        )
    if gravity == 0 and not unknown:
        messages.append("No updateGravity cron line was found.")
    return CronPlan(can_enable, can_edit and gravity == 1, gravity, unknown, messages, None)


def comment_gravity_line(text: str) -> str:
    plan = inspect_cron(text)
    if not plan.can_edit_cron or plan.gravity_lines != 1:
        raise ValueError("refusing to edit this cron file")
    output = []
    seen = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if not seen and stripped and not stripped.startswith("#"):
            if classify_cron_command(_command_portion(stripped)) == "updateGravity":
                output.append("# pi-local-disabled: " + raw)
                seen = True
                continue
        output.append(raw)
    if not seen:
        raise ValueError("updateGravity line disappeared during edit")
    edited = "\n".join(output)
    if text.endswith("\n"):
        edited += "\n"
    return edited


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

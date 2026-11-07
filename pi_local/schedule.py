"""Read-only notes about Pi-hole's stock weekly Gravity cron.

This package does not edit ``/etc/cron.d/pihole`` and does not install a
replacement Gravity timer. Daily Gravity is deferred, not implemented.
"""

from __future__ import annotations

import re

_UPDATE = re.compile(r"(^|\s)pihole\s+(updategravity|-g)(\s|$)")


def stock_gravity_lines(text: str) -> list[str]:
    """Return cron lines that already run Pi-hole's list refresh. Read only."""
    found = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        command = stripped.split(">", 1)[0].lower()
        if _UPDATE.search(command) and "updatepihole" not in command and "-up" not in command:
            found.append(stripped)
    return found

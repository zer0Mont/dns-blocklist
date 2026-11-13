"""Free-space check measured at the moment it runs.

A historical free-space figure is not a current fact and is not used here.
"""

from __future__ import annotations

import shutil
from pathlib import Path


def disk_preflight(path: Path, minimum_free_bytes: int) -> dict:
    if minimum_free_bytes < 0:
        raise ValueError("minimum free bytes must not be negative")
    target = path if path.exists() else path.parent
    if not target.exists():
        target = Path("/")
    usage = shutil.disk_usage(target)
    return {
        "path": str(target),
        "free_bytes": usage.free,
        "total_bytes": usage.total,
        "minimum_free_bytes": minimum_free_bytes,
        "ok": usage.free >= minimum_free_bytes,
        "measured": "now",
    }

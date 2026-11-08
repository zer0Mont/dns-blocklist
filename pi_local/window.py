"""Europe/London civil-day windows.

``from`` and ``until`` are both required by Pi-hole's database summary. Whether
``until`` is inclusive is not verified for this Pi. The installed server's
``/api/docs`` is the authority. Until an operator sets that from those docs,
no until value is sent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

LONDON = "Europe/London"
UNTIL_SEMANTICS = frozenset({"inclusive", "exclusive"})


@dataclass(frozen=True)
class CivilWindow:
    timezone: str
    start: datetime
    end: datetime
    api_from: int
    api_until_if_inclusive: int
    api_until_if_exclusive: int

    @property
    def hours(self) -> int:
        seconds = int(self.end.timestamp() - self.start.timestamp())
        if seconds % 3600 != 0:
            raise ValueError("civil window is not a whole number of hours")
        return seconds // 3600

    def api_until(self, semantics: str | None) -> int | None:
        if semantics == "inclusive":
            return self.api_until_if_inclusive
        if semantics == "exclusive":
            return self.api_until_if_exclusive
        return None

    def as_dict(self, semantics: str | None = None) -> dict:
        return {
            "label": "previous-europe-london-calendar-day",
            "timezone": self.timezone,
            "from": self.start.isoformat(),
            "until": self.end.isoformat(),
            "hours": self.hours,
            "api_from": self.api_from,
            "api_until_if_inclusive": self.api_until_if_inclusive,
            "api_until_if_exclusive": self.api_until_if_exclusive,
            "until_semantics": semantics if semantics in UNTIL_SEMANTICS else "unverified",
            "until_semantics_proven": False,
            "until_note": (
                "An inclusive or exclusive choice is not proof of this Pi-hole's "
                "from/until rule. Confirm it from that installed version's source "
                "or a controlled midnight-boundary query before trusting exact day "
                "totals. Inclusive does not by itself avoid double-counting."
            ),
        }


def _midnight(moment: datetime) -> datetime:
    return moment.replace(hour=0, minute=0, second=0, microsecond=0)


def previous_london_day(now: datetime, timezone: str = LONDON) -> CivilWindow:
    """Previous completed Europe/London civil day, including 23- and 25-hour days."""
    zone = ZoneInfo(timezone)
    local = now.astimezone(zone)
    today_start = _midnight(local)
    previous_date = (today_start - timedelta(hours=20)).date()
    start = datetime(
        previous_date.year,
        previous_date.month,
        previous_date.day,
        0,
        0,
        tzinfo=zone,
    )
    end = today_start
    if end.timestamp() <= start.timestamp():
        raise ValueError("could not resolve the previous Europe/London midnight")
    api_from = int(start.timestamp())
    exclusive = int(end.timestamp())
    inclusive = exclusive - 1
    if inclusive < api_from:
        raise ValueError("empty API window")
    return CivilWindow(timezone, start, end, api_from, inclusive, exclusive)

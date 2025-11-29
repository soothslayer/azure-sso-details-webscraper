# common/time_utils.py
import datetime
from typing import Optional


def parse_iso_utc(dt_str: str) -> Optional[datetime.datetime]:
    if not dt_str:
        return None
    s = dt_str
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def utc_now_rounded_minute() -> datetime.datetime:
    """UTC now, rounded to nearest minute, no seconds."""
    now = datetime.datetime.utcnow()
    if now.second >= 30:
        now = now + datetime.timedelta(minutes=1)
    return now.replace(second=0, microsecond=0)
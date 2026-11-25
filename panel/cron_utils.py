"""Zero-dependency 5-field cron expression validator and scheduler helper."""

from datetime import datetime, timedelta, timezone
from typing import Set


def _parse_field(field: str, min_val: int, max_val: int) -> Set[int]:
    values: Set[int] = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            raise ValueError("Empty cron segment")
        step = 1
        if "/" in part:
            base, step_str = part.split("/", 1)
            step = int(step_str)
            if step <= 0:
                raise ValueError("Cron step must be > 0")
        else:
            base = part

        if base == "*":
            start, end = min_val, max_val
        elif "-" in base:
            s_str, e_str = base.split("-", 1)
            start, end = int(s_str), int(e_str)
            if start < min_val or end > max_val or start > end:
                raise ValueError(f"Range {base} out of bounds [{min_val}, {max_val}]")
        else:
            val = int(base)
            if val < min_val or val > max_val:
                raise ValueError(f"Value {val} out of bounds [{min_val}, {max_val}]")
            start, end = val, val if "/" not in part else max_val

        values.update(range(start, end + 1, step))
    return values


def validate_cron(expr: str) -> bool:
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError("Cron expression must have exactly 5 fields: minute hour day month weekday")
    _parse_field(parts[0], 0, 59)
    _parse_field(parts[1], 0, 23)
    _parse_field(parts[2], 1, 31)
    _parse_field(parts[3], 1, 12)
    _parse_field(parts[4], 0, 6)
    return True


def compute_next_run(expr: str, after: datetime = None) -> str:
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError("Invalid cron expression")
    mins = _parse_field(parts[0], 0, 59)
    hours = _parse_field(parts[1], 0, 23)
    days = _parse_field(parts[2], 1, 31)
    months = _parse_field(parts[3], 1, 12)
    weekdays = _parse_field(parts[4], 0, 6)

    cur = (after or datetime.now(timezone.utc)).replace(second=0, microsecond=0) + timedelta(minutes=1)
    limit = cur + timedelta(days=366)
    while cur <= limit:
        cron_dow = (cur.weekday() + 1) % 7  # Sunday=0 .. Saturday=6
        if cur.month in months and cur.day in days and cron_dow in weekdays and cur.hour in hours and cur.minute in mins:
            return cur.strftime("%Y-%m-%dT%H:%M:%SZ")
        cur += timedelta(minutes=1)
    return (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

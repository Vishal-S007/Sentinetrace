"""Timestamp parsing and normalization to UTC."""

from datetime import UTC, datetime, timedelta, tzinfo

from app.ingestion.types import ParseError

# Events more than this far after the reference time are rejected as implausible.
MAX_FUTURE_SKEW = timedelta(days=1)
MIN_YEAR = 1990

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _finalize(dt: datetime, reference: datetime) -> datetime:
    dt = dt.astimezone(UTC)
    if dt.year < MIN_YEAR:
        raise ParseError("timestamp is implausibly old")
    if dt > reference.astimezone(UTC) + MAX_FUTURE_SKEW:
        raise ParseError("timestamp is in the future")
    return dt


def parse_clf_time(value: str, reference: datetime) -> datetime:
    """Common Log Format time, e.g. '10/Oct/2026:13:55:36 -0700'. The offset is required."""
    try:
        dt = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError as exc:
        raise ParseError("invalid timestamp") from exc
    return _finalize(dt, reference)


def parse_iso_time(value: str, default_tz: tzinfo, reference: datetime) -> datetime:
    """ISO 8601. Naive values are interpreted in the source's configured time zone."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ParseError("invalid timestamp") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return _finalize(dt, reference)


def parse_epoch(value: float, reference: datetime) -> datetime:
    """Unix epoch in seconds, or milliseconds when the number is too large to be seconds."""
    seconds = value / 1000 if abs(value) >= 1e11 else value
    try:
        dt = datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ParseError("invalid timestamp") from exc
    return _finalize(dt, reference)


def parse_syslog_time(value: str, default_tz: tzinfo, reference: datetime) -> datetime:
    """RFC 3164 'Oct 12 10:15:32' (no year, no zone).

    The zone comes from the source's configuration. The year is the reference year, or the
    previous year if that would place the event more than a day in the future (logs that
    span New Year, uploaded in January).
    """
    parts = value.split()
    if len(parts) != 3 or parts[0] not in _MONTHS:
        raise ParseError("invalid timestamp")
    try:
        day = int(parts[1])
        hh, mm, ss = (int(x) for x in parts[2].split(":"))
        ref_local = reference.astimezone(default_tz)
        dt = datetime(ref_local.year, _MONTHS[parts[0]], day, hh, mm, ss, tzinfo=default_tz)
    except ValueError as exc:
        raise ParseError("invalid timestamp") from exc
    if dt.astimezone(UTC) > reference.astimezone(UTC) + MAX_FUTURE_SKEW:
        try:
            dt = dt.replace(year=dt.year - 1)
        except ValueError as exc:  # Feb 29 in a non-leap previous year
            raise ParseError("invalid timestamp") from exc
    return _finalize(dt, reference)

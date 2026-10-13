"""Building blocks for detection rules.

Every rule is deterministic: given the same events and configuration it produces the same
findings. Findings are grouped by (entity, time bucket), where buckets are fixed-size
intervals aligned to the Unix epoch (ST_ALERT_GROUP_MINUTES, default 60). Grouping by a
fixed bucket, rather than by "time since the last alert", makes results independent of the
order in which files are imported, and keeps a burst of thousands of events in one alert.
"""

import re
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar
from urllib.parse import unquote_plus

from pydantic import BaseModel, ConfigDict


@dataclass(frozen=True, slots=True)
class EventRow:
    """The subset of an event that rules look at."""

    id: int
    event_time: datetime
    event_type: str
    source_ip: str | None
    username: str | None
    http_method: str | None
    path: str | None
    query: str | None
    http_status: int | None
    user_agent: str | None
    referrer: str | None
    attributes: dict[str, Any]


@dataclass
class Finding:
    """One group that met a rule's condition. Becomes (or updates) one alert."""

    entity_key: str  # stable identity of the group within the bucket, e.g. "ip=1.2.3.4"
    bucket_start: datetime
    event_ids: list[int]  # supporting events, ascending by (event_time, id)
    first_seen: datetime
    last_seen: datetime
    title: str
    reason: str
    confidence: str  # low | medium | high
    confidence_reason: str
    source_ip: str | None = None
    username: str | None = None
    endpoint: str | None = None
    indicators: dict[int, str] = field(default_factory=dict)  # event id -> indicator name
    details: dict[str, Any] = field(default_factory=dict)


class RuleConfig(BaseModel):
    """Base for each rule's validated, editable configuration."""

    model_config = ConfigDict(extra="forbid")


class Rule:
    """A detection rule. Subclasses set the metadata and implement evaluate()."""

    rule_id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[str]
    description: ClassVar[str]
    default_severity: ClassVar[str]
    config_model: ClassVar[type[RuleConfig]]
    recommended_steps: ClassVar[list[str]]
    # SQL-side prefilter, applied before Python matching (see engine.fetch_events).
    event_types: ClassVar[tuple[str, ...] | None] = ("http_request",)
    statuses: ClassVar[tuple[int, ...] | None] = None

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = self.config_model.model_validate(config)

    @classmethod
    def default_config(cls) -> dict[str, Any]:
        return cls.config_model().model_dump()

    def lookback_seconds(self) -> int:
        """How far before a bucket's start events must be read (sliding windows)."""
        return 0

    def window_seconds(self) -> int:
        return 0

    def evaluate(
        self, events: Sequence[EventRow], bucket: timedelta, buckets: set[datetime]
    ) -> list[Finding]:
        raise NotImplementedError


# --- Time buckets ----------------------------------------------------------------------

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def bucket_of(ts: datetime, size: timedelta) -> datetime:
    n = (ts - EPOCH) // size
    return EPOCH + n * size


def buckets_between(start: datetime, end: datetime, size: timedelta) -> list[datetime]:
    out, b = [], bucket_of(start, size)
    while b <= end:
        out.append(b)
        b += size
    return out


def group_by(
    events: Iterable[EventRow], key: Callable[[EventRow], str | None]
) -> dict[str, list[EventRow]]:
    groups: dict[str, list[EventRow]] = {}
    for e in events:
        k = key(e)
        if k is not None:
            groups.setdefault(k, []).append(e)
    return groups


def sliding_window_hits(
    events: Sequence[EventRow],
    window: timedelta,
    bucket: timedelta,
    buckets: set[datetime],
    satisfied: Callable[[Sequence[EventRow]], bool],
) -> dict[datetime, tuple[set[int], int]]:
    """For time-ordered events of one entity, find windows (t_end - window, t_end] whose
    contents satisfy the condition, and attribute them to the bucket of t_end.

    Returns {bucket_start: (supporting event ids, peak window size)} for requested buckets.

    * A window may reach back into the previous bucket, so a burst straddling a bucket
      boundary is still detected; the alert belongs to the bucket where the threshold was met.
    * Events already claimed by a satisfying window that ended in an earlier bucket are not
      counted again, so consecutive alerts never double-count events.
    * Callers must supply events from at least 2 x window before the first requested bucket
      (Rule.lookback_seconds) so those earlier windows are computed completely.
    """
    per_bucket: dict[datetime, tuple[set[int], int]] = {}
    win: deque[EventRow] = deque()
    for e in events:
        win.append(e)
        while win and win[0].event_time <= e.event_time - window:
            win.popleft()
        if not satisfied(win):
            continue
        b = bucket_of(e.event_time, bucket)
        ids, peak = per_bucket.get(b, (set(), 0))
        ids.update(x.id for x in win)
        per_bucket[b] = (ids, max(peak, len(win)))

    hits: dict[datetime, tuple[set[int], int]] = {}
    claimed: set[int] = set()
    for b in sorted(per_bucket):
        ids, peak = per_bucket[b]
        if b in buckets:
            hits[b] = (ids - claimed, peak)
        claimed |= ids
    return hits


# --- Request-data normalization for indicator matching -------------------------------


def decode(value: str | None, rounds: int = 3) -> str:
    """URL-decode repeatedly (catches double encoding) and lowercase."""
    if not value:
        return ""
    out = value
    for _ in range(rounds):
        nxt = unquote_plus(out)
        if nxt == out:
            break
        out = nxt
    return out.lower()


def scan(patterns: dict[str, re.Pattern[str]], text: str) -> list[str]:
    return [name for name, pattern in patterns.items() if pattern.search(text)]


def iter_fields(e: EventRow, include_headers: bool) -> Iterator[tuple[str, str]]:
    yield "path", e.path or ""
    yield "query", e.query or ""
    if include_headers:
        yield "user_agent", e.user_agent or ""
        yield "referrer", e.referrer or ""


def fmt_time(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def span(events: Sequence[EventRow]) -> tuple[datetime, datetime]:
    return events[0].event_time, events[-1].event_time


def top(values: Iterable[str | None], n: int = 5) -> list[str]:
    counts: dict[str, int] = {}
    for v in values:
        if v:
            counts[v] = counts.get(v, 0) + 1
    return [k for k, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]

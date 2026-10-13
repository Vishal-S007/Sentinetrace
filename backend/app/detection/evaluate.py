"""Compare detection output with a labelled dataset's ground truth.

Metrics are only meaningful for the dataset they are computed on. For the bundled
synthetic dataset they show that the rules behave as designed on the scripted scenarios
and on the deliberately tricky benign traffic, not how they perform on real-world logs.
"""

from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.engine import group_key
from app.models import Alert, AlertEvent, Event, ImportedFile


@dataclass
class Metrics:
    expected_alerts: int
    produced_alerts: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    benign_entities: int
    benign_entities_alerted: int
    false_positive_rate: float  # share of benign IPs that appear in any alert
    evidence_events: int
    evidence_events_malicious: int
    evidence_precision: float  # share of linked evidence events labelled malicious
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ratio(num: int, den: int) -> float:
    return round(num / den, 4) if den else 1.0


def evaluate(db: Session, truth: dict[str, Any], file_ids: dict[str, int]) -> Metrics:
    """file_ids maps dataset file names (as in truth["malicious_lines"]) to imported file ids."""
    expected = {
        (a["rule_id"], group_key(a["entity"], _parse(a["bucket_start"])))
        for a in truth["expected_alerts"]
    }
    alerts = db.scalars(select(Alert)).all()
    produced = {(a.rule_id, a.group_key) for a in alerts}
    tp = expected & produced

    benign = set(truth["benign_ips"])
    alerted_ips = {str(a.source_ip) for a in alerts if a.source_ip is not None}
    benign_alerted = benign & alerted_ips

    malicious = {
        (file_ids[name], line)
        for name, scenarios in truth["malicious_lines"].items()
        if name in file_ids
        for lines in scenarios.values()
        for line in lines
    }
    evidence = db.execute(
        select(Event.file_id, Event.line_number)
        .join(AlertEvent, AlertEvent.event_id == Event.id)
        .distinct()
    ).all()
    evidence_set = {(f, n) for f, n in evidence}
    evidence_bad = evidence_set & malicious

    return Metrics(
        expected_alerts=len(expected),
        produced_alerts=len(produced),
        true_positives=len(tp),
        false_positives=len(produced - expected),
        false_negatives=len(expected - produced),
        precision=_ratio(len(tp), len(produced)),
        recall=_ratio(len(tp), len(expected)),
        benign_entities=len(benign),
        benign_entities_alerted=len(benign_alerted),
        false_positive_rate=_ratio(len(benign_alerted), len(benign)) if benign else 0.0,
        evidence_events=len(evidence_set),
        evidence_events_malicious=len(evidence_bad),
        evidence_precision=_ratio(len(evidence_bad), len(evidence_set)),
        missing=sorted(f"{r} {k}" for r, k in expected - produced),
        unexpected=sorted(f"{r} {k}" for r, k in produced - expected),
    )


def _parse(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value)


def file_ids_by_name(db: Session, ids: list[int]) -> dict[str, int]:
    return {
        f.original_filename: f.id
        for f in db.scalars(select(ImportedFile).where(ImportedFile.id.in_(ids))).all()
    }

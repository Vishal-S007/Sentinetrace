"""Incident timeline and exportable report (Markdown or JSON)."""

import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, AuditLog, Event, Incident
from app.schemas.detection import AlertOut, NoteOut
from app.schemas.incidents import TimelineItem

EVIDENCE_LINES_PER_ALERT = 5
NOTE_TITLES = {"note": "Note", "action": "Action taken", "evidence": "Evidence reference"}
CHANGE_LABELS = {
    "title": "Title",
    "summary": "Summary",
    "status": "Status",
    "severity": "Severity",
    "assignee": "Owner",
}


def _change_text(changes: dict[str, Any]) -> str:
    parts = []
    for field, change in changes.items():
        label = CHANGE_LABELS.get(field, field)
        if field == "summary":
            parts.append(f"{label} updated")
        else:
            before = change.get("from") or "none"
            after = change.get("to") or "none"
            parts.append(f"{label}: {before} → {after}")
    return "; ".join(parts)


def _audit_item(entry: AuditLog) -> TimelineItem | None:
    d = entry.details or {}
    if entry.action == "incident.create":
        ids = d.get("alert_ids") or []
        detail = f"With alerts {', '.join(f'#{i}' for i in ids)}" if ids else None
        title = "Incident created"
    elif entry.action == "incident.update":
        title = _change_text(d.get("changes", {})) or "Incident updated"
        detail = d.get("note") or None
    elif entry.action == "incident.link_alerts":
        title = "Linked " + ", ".join(f"alert #{i}" for i in d.get("alert_ids", []))
        detail = None
    elif entry.action == "incident.unlink_alert":
        title = f"Removed alert #{d.get('alert_id')}"
        detail = None
    elif entry.action == "incident.export":
        title = f"Report exported ({d.get('format', 'unknown')})"
        detail = None
    else:  # notes are shown from the notes table, with their text
        return None
    return TimelineItem(
        at=entry.occurred_at, kind="change", title=title, detail=detail, actor=entry.actor_username
    )


def build_timeline(
    db: Session, incident: Incident, alerts: list[AlertOut], notes: list[NoteOut]
) -> list[TimelineItem]:
    items: list[TimelineItem] = []
    for a in alerts:
        items.append(
            TimelineItem(
                at=a.first_seen, kind="observed", title=f"First observed: {a.title}", alert_id=a.id
            )
        )
        if a.last_seen != a.first_seen:
            items.append(
                TimelineItem(
                    at=a.last_seen,
                    kind="observed",
                    title=f"Last observed: {a.title} ({a.event_count} events)",
                    alert_id=a.id,
                )
            )
    entries = db.scalars(
        select(AuditLog)
        .where(AuditLog.target_type == "incident", AuditLog.target_id == str(incident.id))
        .order_by(AuditLog.id)
        .limit(2000)
    ).all()
    items += [i for i in (_audit_item(e) for e in entries) if i is not None]
    items += [
        TimelineItem(
            at=n.created_at,
            kind="note",
            title=NOTE_TITLES[n.kind],
            detail=n.body,
            actor=n.author,
            event_id=n.event_id,
        )
        for n in notes
    ]
    order = {"observed": 0, "change": 1, "note": 2}
    return sorted(items, key=lambda i: (i.at, order[i.kind]))


def evidence_samples(db: Session, alert_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
    """The first few evidence lines of each alert, in time order."""
    out: dict[int, list[dict[str, Any]]] = {}
    for alert_id in alert_ids:
        rows = db.execute(
            select(Event.id, Event.event_time, Event.raw_line, AlertEvent.indicator)
            .join(AlertEvent, AlertEvent.event_id == Event.id)
            .where(AlertEvent.alert_id == alert_id)
            .order_by(Event.event_time, Event.id)
            .limit(EVIDENCE_LINES_PER_ALERT)
        ).all()
        out[alert_id] = [
            {
                "event_id": r.id,
                "event_time": r.event_time,
                "indicator": r.indicator,
                "raw_line": r.raw_line,
            }
            for r in rows
        ]
    return out


def report_data(db: Session, detail: dict[str, Any], generated_by: str) -> dict[str, Any]:
    alerts = detail["alerts"]
    reasons = dict(
        db.execute(select(Alert.id, Alert.reason).where(Alert.id.in_([a.id for a in alerts]))).all()
    )
    samples = evidence_samples(db, [a.id for a in alerts])
    return {
        "generated_at": datetime.now(UTC),
        "generated_by": generated_by,
        "incident": {
            k: detail[k]
            for k in (
                "id",
                "title",
                "summary",
                "status",
                "severity",
                "assignee",
                "created_by",
                "created_at",
                "updated_at",
                "closed_at",
                "alert_count",
            )
        },
        "alerts": [
            {
                **a.model_dump(),
                "reason": reasons.get(a.id, ""),
                "evidence_sample": samples.get(a.id, []),
            }
            for a in alerts
        ],
        "timeline": [t.model_dump() for t in detail["timeline"]],
        "notes": [n.model_dump() for n in detail["notes"]],
        "disclaimer": (
            "Alerts are indicators derived from log data. They do not by themselves "
            "confirm that an attack succeeded or that a system was compromised."
        ),
    }


def _ts(v: datetime | None) -> str:
    return v.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC") if v else "—"


def _cell(v: Any) -> str:
    """A Markdown table cell: no line breaks, pipes escaped."""
    return re.sub(r"\s+", " ", str(v if v is not None else "—")).replace("|", "\\|")


def _fence(lines: list[str]) -> str:
    """A code fence longer than any backtick run inside, so log content can't break out."""
    longest = max((len(m) for line in lines for m in re.findall(r"`+", line)), default=0)
    fence = "`" * max(3, longest + 1)
    return "\n".join([fence, *lines, fence])


def render_markdown(data: dict[str, Any]) -> str:
    inc = data["incident"]
    out = [
        f"# Incident #{inc['id']}: {_cell(inc['title'])}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Status | {inc['status']} |",
        f"| Severity | {inc['severity']} |",
        f"| Owner | {_cell(inc['assignee'] or 'unassigned')} |",
        f"| Created | {_ts(inc['created_at'])} by {_cell(inc['created_by'])} |",
        f"| Last updated | {_ts(inc['updated_at'])} |",
        f"| Closed | {_ts(inc['closed_at'])} |",
        f"| Linked alerts | {inc['alert_count']} |",
        "",
        f"> {data['disclaimer']}",
        "",
        "## Summary",
        "",
        inc["summary"].strip() or "_No summary recorded._",
        "",
        "## Linked alerts",
        "",
    ]
    if data["alerts"]:
        out += [
            "| ID | Rule | Severity | Status | Source IP | First seen | Last seen | Events |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for a in data["alerts"]:
            out.append(
                f"| #{a['id']} | {a['rule_id']} | {a['severity']} | {a['status']} | "
                f"{_cell(a['source_ip'])} | {_ts(a['first_seen'])} | {_ts(a['last_seen'])} | "
                f"{a['event_count']} |"
            )
        for a in data["alerts"]:
            out += ["", f"### Alert #{a['id']}: {_cell(a['title'])}", "", _cell(a["reason"]), ""]
            if a["evidence_sample"]:
                out.append(
                    f"Evidence sample (first {len(a['evidence_sample'])} "
                    f"of {a['event_count']} events):"
                )
                out.append("")
                out.append(_fence([e["raw_line"] for e in a["evidence_sample"]]))
    else:
        out.append("_No alerts linked._")
    out += ["", "## Timeline", ""]
    for t in data["timeline"]:
        who = f" ({_cell(t['actor'])})" if t["actor"] else ""
        line = f"- **{_ts(t['at'])}** — {_cell(t['title'])}{who}"
        if t["detail"]:
            line += f": {_cell(t['detail'])}"
        out.append(line)
    if not data["timeline"]:
        out.append("_No timeline entries._")
    out += [
        "",
        "---",
        f"Generated {_ts(data['generated_at'])} by {_cell(data['generated_by'])} "
        "with SentinelTrace.",
        "",
    ]
    return "\n".join(out)

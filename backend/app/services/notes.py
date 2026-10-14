"""Append-only investigation notes on alerts and incidents."""

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Event, InvestigationNote, User
from app.schemas.detection import NoteCreate, NoteOut
from app.services.people import usernames

MAX_NOTES_LISTED = 2000


def add_note(
    db: Session,
    body: NoteCreate,
    author: User,
    *,
    alert_id: int | None = None,
    incident_id: int | None = None,
) -> InvestigationNote:
    if body.event_id is not None and db.get(Event, body.event_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "event_id does not exist")
    note = InvestigationNote(
        alert_id=alert_id,
        incident_id=incident_id,
        kind=body.kind,
        body=body.body,
        event_id=body.event_id,
        author_id=author.id,
    )
    db.add(note)
    db.flush()
    return note


def list_notes(
    db: Session, *, alert_id: int | None = None, incident_id: int | None = None
) -> list[NoteOut]:
    stmt = select(InvestigationNote).order_by(InvestigationNote.id)
    if alert_id is not None:
        stmt = stmt.where(InvestigationNote.alert_id == alert_id)
    else:
        stmt = stmt.where(InvestigationNote.incident_id == incident_id)
    rows = db.scalars(stmt.limit(MAX_NOTES_LISTED)).all()
    names = usernames(db, (n.author_id for n in rows))
    return [note_out(n, names) for n in rows]


def note_out(n: InvestigationNote, names: dict[int, str]) -> NoteOut:
    return NoteOut(
        id=n.id,
        kind=n.kind,  # type: ignore[arg-type]
        body=n.body,
        event_id=n.event_id,
        author=names.get(n.author_id, "unknown"),
        created_at=n.created_at,
    )

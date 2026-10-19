"""Facts the privacy policy, terms and cookie policy pages show (public, read-only).

Everything here comes from settings: who operates this instance, and how long each kind
of personal data is kept. Nothing about any user is returned.
"""

from datetime import date

from fastapi import APIRouter
from pydantic import BaseModel

from app.api.deps import CSRF_COOKIE, SESSION_COOKIE, AppSettings

router = APIRouter(tags=["legal"])


class Operator(BaseModel):
    name: str
    contact: str
    address: str


class RetentionFacts(BaseModel):
    login_attempt_days: int
    session_retention_days: int
    session_idle_minutes: int
    session_absolute_hours: int
    data_retention_days: int | None
    data_retention_min_days: int


class CookieFact(BaseModel):
    name: str
    purpose: str
    duration_hours: int
    http_only: bool
    same_site: str


class LegalFacts(BaseModel):
    operator: Operator
    effective_date: date
    retention: RetentionFacts
    cookies: list[CookieFact]


@router.get("/legal", response_model=LegalFacts, summary="Facts shown on the legal pages")
def legal(settings: AppSettings) -> LegalFacts:
    hours = settings.session_absolute_hours
    return LegalFacts(
        operator=Operator(
            name=settings.operator_name,
            contact=settings.operator_contact,
            address=settings.operator_address,
        ),
        effective_date=settings.legal_effective_date,
        retention=RetentionFacts(
            login_attempt_days=settings.login_attempt_retention_days,
            session_retention_days=settings.session_retention_days,
            session_idle_minutes=settings.session_idle_minutes,
            session_absolute_hours=hours,
            data_retention_days=settings.retention_auto_days,
            data_retention_min_days=settings.retention_min_days,
        ),
        cookies=[
            CookieFact(
                name=SESSION_COOKIE,
                purpose="Keeps you signed in. Holds a random session token.",
                duration_hours=hours,
                http_only=True,
                same_site="Lax",
            ),
            CookieFact(
                name=CSRF_COOKIE,
                purpose="Protects your account against forged requests from other sites.",
                duration_hours=hours,
                http_only=False,
                same_site="Strict",
            ),
        ],
    )

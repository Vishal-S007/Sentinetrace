"""All detection rules, keyed by rule id."""

from app.detection.base import Rule
from app.detection.rules.auth import BruteForce, RepeatedAuthFailures
from app.detection.rules.correlation import MultiStageActivity
from app.detection.rules.web_indicators import (
    PathTraversalIndicators,
    SqlInjectionIndicators,
    SuspiciousMethods,
    XssIndicators,
)
from app.detection.rules.web_volume import NotFoundRecon, RepeatedAccessDenied, RequestBurst

RULES: dict[str, type[Rule]] = {
    r.rule_id: r
    for r in (
        RepeatedAuthFailures,
        BruteForce,
        SqlInjectionIndicators,
        XssIndicators,
        PathTraversalIndicators,
        RequestBurst,
        RepeatedAccessDenied,
        NotFoundRecon,
        SuspiciousMethods,
        MultiStageActivity,
    )
}
CORRELATION_RULE_ID = MultiStageActivity.rule_id

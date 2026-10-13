"""Authentication rules: repeated failures and brute force / password spraying."""

from collections.abc import Sequence
from datetime import datetime, timedelta

from pydantic import Field

from app.detection.base import (
    EventRow,
    Finding,
    Rule,
    RuleConfig,
    fmt_time,
    group_by,
    sliding_window_hits,
)


class RepeatedFailuresConfig(RuleConfig):
    threshold: int = Field(default=5, ge=2, le=10_000, description="Failures within the window")
    window_seconds: int = Field(default=300, ge=10, le=86_400)


class RepeatedAuthFailures(Rule):
    rule_id = "ST-AUTH-001"
    name = "Repeated authentication failures"
    category = "authentication"
    description = (
        "The same account failed to authenticate repeatedly from the same source within a "
        "short window. Often a forgotten password or a misconfigured client; can also be a "
        "targeted password-guessing attempt."
    )
    default_severity = "medium"
    config_model = RepeatedFailuresConfig
    event_types = ("auth_failure",)
    recommended_steps = [
        "Check whether the account owner recognises the attempts (time, source IP, client).",
        "Look for a successful login for the same account shortly after the failures.",
        "Check whether the source IP also targets other accounts (see ST-AUTH-002).",
        "If unexpected, consider resetting the password and enforcing MFA for the account.",
    ]

    def lookback_seconds(self) -> int:
        return 2 * self.config.window_seconds

    def window_seconds(self) -> int:
        return self.config.window_seconds

    def evaluate(
        self, events: Sequence[EventRow], bucket: timedelta, buckets: set[datetime]
    ) -> list[Finding]:
        cfg: RepeatedFailuresConfig = self.config  # type: ignore[assignment]

        def key(e: EventRow) -> str | None:
            if not e.username and not e.source_ip:
                return None
            return f"user={e.username or '-'}|ip={e.source_ip or '-'}"

        findings = []
        for entity, evs in group_by(events, key).items():
            hits = sliding_window_hits(
                evs,
                timedelta(seconds=cfg.window_seconds),
                bucket,
                buckets,
                lambda w: len(w) >= cfg.threshold,
            )
            for b, (ids, peak) in hits.items():
                support = [e for e in evs if e.id in ids]
                user, ip = support[0].username, support[0].source_ip
                who = f"account '{user}'" if user else "an unknown account"
                frm = f" from {ip}" if ip else ""
                strong = peak >= 2 * cfg.threshold
                t0, t1 = fmt_time(support[0].event_time), fmt_time(support[-1].event_time)
                findings.append(
                    Finding(
                        entity_key=entity,
                        bucket_start=b,
                        event_ids=[e.id for e in support],
                        first_seen=support[0].event_time,
                        last_seen=support[-1].event_time,
                        title=f"Repeated authentication failures for {who}{frm}",
                        reason=(
                            f"{len(support)} failed authentications for {who}{frm} between "
                            f"{t0} and {t1}; peak {peak} within {cfg.window_seconds}s "
                            f"(threshold {cfg.threshold}). Indicator only: failures do not "
                            "show that the account was accessed."
                        ),
                        confidence="high" if strong else "medium",
                        confidence_reason=(
                            f"Peak of {peak} failures is at least twice the threshold."
                            if strong
                            else f"Peak of {peak} failures meets the threshold of "
                            f"{cfg.threshold}; a single user mistyping a password can "
                            "produce this."
                        ),
                        source_ip=ip,
                        username=user,
                        details={"peak_in_window": peak},
                    )
                )
        return findings


class BruteForceConfig(RuleConfig):
    failures_threshold: int = Field(default=20, ge=2, le=100_000)
    distinct_users_threshold: int = Field(default=5, ge=2, le=10_000)
    window_seconds: int = Field(default=600, ge=10, le=86_400)


class BruteForce(Rule):
    rule_id = "ST-AUTH-002"
    name = "Potential brute force or password spraying"
    category = "authentication"
    description = (
        "One source IP produced many authentication failures, or failures against many "
        "different accounts, within the window. A success from the same IP during the "
        "activity is highlighted because it may indicate a guessed credential."
    )
    default_severity = "high"
    config_model = BruteForceConfig
    event_types = ("auth_failure", "auth_success")
    recommended_steps = [
        "Identify every account targeted from this IP and whether any login succeeded.",
        "If a success is shown, treat that account as potentially compromised: review its "
        "activity after the login, reset credentials and revoke sessions.",
        "Consider blocking or rate-limiting the source IP at the edge.",
        "Check other sources (web, VPN, mail) for activity from the same IP.",
    ]

    def lookback_seconds(self) -> int:
        return 2 * self.config.window_seconds

    def window_seconds(self) -> int:
        return self.config.window_seconds

    def evaluate(
        self, events: Sequence[EventRow], bucket: timedelta, buckets: set[datetime]
    ) -> list[Finding]:
        cfg: BruteForceConfig = self.config  # type: ignore[assignment]
        window = timedelta(seconds=cfg.window_seconds)

        def satisfied(w: Sequence[EventRow]) -> bool:
            return len(w) >= cfg.failures_threshold or (
                len({e.username for e in w if e.username}) >= cfg.distinct_users_threshold
            )

        findings = []
        for ip, evs in group_by(events, lambda e: e.source_ip).items():
            failures = [e for e in evs if e.event_type == "auth_failure"]
            successes = [e for e in evs if e.event_type == "auth_success"]
            for b, (ids, peak) in sliding_window_hits(
                failures, window, bucket, buckets, satisfied
            ).items():
                support = [e for e in failures if e.id in ids]
                start, end = support[0].event_time, support[-1].event_time
                users = sorted({e.username for e in support if e.username})
                # Successes from the same IP during the activity (or shortly after).
                wins = [s for s in successes if start <= s.event_time <= end + window]
                indicators = {e.id: "auth_failure" for e in support}
                indicators.update({s.id: "auth_success_after_failures" for s in wins})
                by_id = {e.id: e for e in [*support, *wins]}
                ordered = sorted(by_id.values(), key=lambda e: (e.event_time, e.id))
                findings.append(
                    Finding(
                        entity_key=f"ip={ip}",
                        bucket_start=b,
                        event_ids=[e.id for e in ordered],
                        first_seen=ordered[0].event_time,
                        last_seen=ordered[-1].event_time,
                        title=f"Potential brute force from {ip} ({len(users)} account"
                        f"{'s' if len(users) != 1 else ''})",
                        reason=(
                            f"{len(support)} failed authentications from {ip} against "
                            f"{len(users)} account(s) between {fmt_time(start)} and "
                            f"{fmt_time(end)};"
                            f" peak {peak} within {cfg.window_seconds}s."
                            + (
                                f" {len(wins)} successful login(s) from the same IP followed: "
                                f"{', '.join(sorted({s.username or '?' for s in wins}))}."
                                if wins
                                else ""
                            )
                            + " Indicator only: this does not confirm that any account "
                            "was accessed."
                        ),
                        confidence="high"
                        if wins
                        or len(users) >= cfg.distinct_users_threshold
                        or peak >= 2 * cfg.failures_threshold
                        else "medium",
                        confidence_reason=(
                            "A successful login from the same IP followed the failures."
                            if wins
                            else f"Failures spread across {len(users)} accounts (password-spraying "
                            "pattern)."
                            if len(users) >= cfg.distinct_users_threshold
                            else f"Failure volume ({peak} in window) is well above the threshold."
                            if peak >= 2 * cfg.failures_threshold
                            else "Failure volume meets the threshold; no success was observed."
                        ),
                        source_ip=ip,
                        username=users[0] if len(users) == 1 else None,
                        indicators=indicators,
                        details={
                            "targeted_users": users[:50],
                            "peak_in_window": peak,
                            "successful_logins": [s.username for s in wins][:20],
                        },
                    )
                )
        return findings

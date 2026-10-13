"""Volume rules: request bursts, repeated 401/403, 404 bursts and reconnaissance."""

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
    top,
)


def _window_finding(
    rule: Rule,
    ip: str,
    b: datetime,
    support: list[EventRow],
    peak: int,
    threshold: int,
    window: int,
    title: str,
    what: str,
    extra: str = "",
    strong: bool | None = None,
    strong_reason: str | None = None,
    details: dict | None = None,
) -> Finding:
    strong = peak >= 2 * threshold if strong is None else strong
    endpoints = top(e.path for e in support)
    return Finding(
        entity_key=f"ip={ip}",
        bucket_start=b,
        event_ids=[e.id for e in support],
        first_seen=support[0].event_time,
        last_seen=support[-1].event_time,
        title=title,
        reason=(
            f"{len(support)} {what} from {ip} between {fmt_time(support[0].event_time)} and "
            f"{fmt_time(support[-1].event_time)}; peak {peak} within {window}s "
            f"(threshold {threshold}).{extra} Indicator only: request volume does not by "
            "itself show malicious intent or any impact."
        ),
        confidence="high" if strong else "medium",
        confidence_reason=strong_reason
        or (
            f"Peak of {peak} is at least twice the threshold of {threshold}."
            if strong
            else f"Peak of {peak} meets the threshold of {threshold}; busy legitimate clients "
            "(crawlers, monitoring, NAT gateways) can also do this."
        ),
        source_ip=ip,
        endpoint=endpoints[0] if endpoints else None,
        details={"peak_in_window": peak, "top_endpoints": endpoints, **(details or {})},
    )


class BurstConfig(RuleConfig):
    threshold: int = Field(default=300, ge=2, le=1_000_000, description="Requests in window")
    window_seconds: int = Field(default=60, ge=1, le=86_400)


class RequestBurst(Rule):
    rule_id = "ST-WEB-004"
    name = "High-frequency request burst"
    category = "web"
    description = "One source IP sent an unusually high number of requests in a short window."
    default_severity = "medium"
    config_model = BurstConfig
    recommended_steps = [
        "Check whether the IP belongs to a known crawler, monitor or partner integration.",
        "Look at which endpoints were hit: login, search and API endpoints suggest abuse.",
        "Correlate with other alerts from the same IP (scanning, injection, brute force).",
        "Consider rate limiting at the edge if the traffic is unwanted.",
    ]

    def lookback_seconds(self) -> int:
        return 2 * self.config.window_seconds

    def window_seconds(self) -> int:
        return self.config.window_seconds

    def evaluate(
        self, events: Sequence[EventRow], bucket: timedelta, buckets: set[datetime]
    ) -> list[Finding]:
        cfg: BurstConfig = self.config  # type: ignore[assignment]
        out = []
        for ip, evs in group_by(events, lambda e: e.source_ip).items():
            hits = sliding_window_hits(
                evs,
                timedelta(seconds=cfg.window_seconds),
                bucket,
                buckets,
                lambda w: len(w) >= cfg.threshold,
            )
            for b, (ids, peak) in hits.items():
                support = [e for e in evs if e.id in ids]
                out.append(
                    _window_finding(
                        self,
                        ip,
                        b,
                        support,
                        peak,
                        cfg.threshold,
                        cfg.window_seconds,
                        f"High request rate from {ip}",
                        "requests",
                    )
                )
        return out


class AuthzDeniedConfig(RuleConfig):
    threshold: int = Field(default=15, ge=2, le=100_000)
    window_seconds: int = Field(default=300, ge=10, le=86_400)


class RepeatedAccessDenied(Rule):
    rule_id = "ST-WEB-005"
    name = "Repeated HTTP 401/403 responses"
    category = "web"
    description = (
        "One source IP received many 401 (unauthenticated) or 403 (forbidden) responses in a "
        "short window: credential guessing against HTTP auth/APIs, or probing protected paths."
    )
    default_severity = "medium"
    config_model = AuthzDeniedConfig
    statuses = (401, 403)
    recommended_steps = [
        "Identify the protected endpoints being requested.",
        "For 401s on login/API endpoints, check for credential stuffing and any subsequent 200s.",
        "For 403s, check whether the paths are admin or internal areas being probed.",
    ]

    def lookback_seconds(self) -> int:
        return 2 * self.config.window_seconds

    def window_seconds(self) -> int:
        return self.config.window_seconds

    def evaluate(
        self, events: Sequence[EventRow], bucket: timedelta, buckets: set[datetime]
    ) -> list[Finding]:
        cfg: AuthzDeniedConfig = self.config  # type: ignore[assignment]
        out = []
        for ip, evs in group_by(events, lambda e: e.source_ip).items():
            hits = sliding_window_hits(
                evs,
                timedelta(seconds=cfg.window_seconds),
                bucket,
                buckets,
                lambda w: len(w) >= cfg.threshold,
            )
            for b, (ids, peak) in hits.items():
                support = [e for e in evs if e.id in ids]
                n401 = sum(1 for e in support if e.http_status == 401)
                out.append(
                    _window_finding(
                        self,
                        ip,
                        b,
                        support,
                        peak,
                        cfg.threshold,
                        cfg.window_seconds,
                        f"Repeated 401/403 responses to {ip}",
                        "401/403 responses",
                        extra=f" {n401} were 401 and {len(support) - n401} were 403.",
                        details={"count_401": n401, "count_403": len(support) - n401},
                    )
                )
        return out


class ReconConfig(RuleConfig):
    not_found_threshold: int = Field(default=30, ge=2, le=100_000)
    distinct_paths_threshold: int = Field(default=20, ge=2, le=100_000)
    window_seconds: int = Field(default=300, ge=10, le=86_400)
    recon_paths: list[str] = Field(
        default=[
            "/.env",
            "/.git",
            "/wp-admin",
            "/wp-login.php",
            "/phpmyadmin",
            "/admin",
            "/server-status",
            "/.aws",
            "/backup",
            "/actuator",
            "/cgi-bin",
            "/config",
            "/.ds_store",
            "/vendor/phpunit",
        ],
        max_length=200,
        description="Path prefixes typical of automated scanners (case-insensitive)",
    )


class NotFoundRecon(Rule):
    rule_id = "ST-WEB-006"
    name = "404 burst and reconnaissance-like requests"
    category = "web"
    description = (
        "One source IP produced many 404 responses or requested many distinct non-existent "
        "paths in a short window, typical of automated content discovery and vulnerability "
        "scanning."
    )
    default_severity = "medium"
    config_model = ReconConfig
    statuses = (404,)
    recommended_steps = [
        "Review the requested paths: known scanner wordlists (/.env, /.git, /wp-admin) indicate "
        "automated reconnaissance.",
        "Check whether any probed path returned 200 from this IP (exposed files).",
        "Correlate with injection or brute-force alerts from the same IP.",
    ]

    def lookback_seconds(self) -> int:
        return 2 * self.config.window_seconds

    def window_seconds(self) -> int:
        return self.config.window_seconds

    def evaluate(
        self, events: Sequence[EventRow], bucket: timedelta, buckets: set[datetime]
    ) -> list[Finding]:
        cfg: ReconConfig = self.config  # type: ignore[assignment]
        prefixes = tuple(p.lower() for p in cfg.recon_paths)

        def satisfied(w: Sequence[EventRow]) -> bool:
            return len(w) >= cfg.not_found_threshold or (
                len({e.path for e in w}) >= cfg.distinct_paths_threshold
            )

        out = []
        for ip, evs in group_by(events, lambda e: e.source_ip).items():
            hits = sliding_window_hits(
                evs, timedelta(seconds=cfg.window_seconds), bucket, buckets, satisfied
            )
            for b, (ids, peak) in hits.items():
                support = [e for e in evs if e.id in ids]
                distinct = len({e.path for e in support})
                recon = sorted(
                    {e.path for e in support if e.path and e.path.lower().startswith(prefixes)}
                )
                strong = len(recon) >= 3
                out.append(
                    _window_finding(
                        self,
                        ip,
                        b,
                        support,
                        peak,
                        cfg.not_found_threshold,
                        cfg.window_seconds,
                        f"404 burst / reconnaissance from {ip}",
                        "404 responses",
                        extra=f" {distinct} distinct paths; {len(recon)} match known scanner "
                        "paths.",
                        strong=strong,
                        strong_reason=(
                            f"{len(recon)} requested paths match known scanner wordlists "
                            f"({', '.join(recon[:5])})."
                            if strong
                            else "Volume of 404s meets the threshold, but few known scanner paths; "
                            "broken links or a misconfigured client can also cause this."
                        ),
                        details={"distinct_paths": distinct, "scanner_paths": recon[:50]},
                    )
                )
        return out

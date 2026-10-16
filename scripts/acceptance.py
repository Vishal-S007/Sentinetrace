#!/usr/bin/env python3
"""End-to-end acceptance check against a running SentinelTrace instance.

Walks the final delivery criteria of docs/REQUIREMENTS.md (section 14) through the
public API only, using the bundled synthetic datasets, and prints PASS/FAIL with the
evidence for each check. Standard library only: runs with any Python 3.11+.

Run it against a FRESH installation (it imports the datasets and compares the resulting
alerts with the ground truth):

    python3 scripts/acceptance.py --base-url http://localhost:8080 --username admin
    # password from ST_ACCEPTANCE_PASSWORD, or prompted

It creates two temporary users (a viewer and an analyst), four log sources, and one
incident; it changes the status of one alert. Exit code 0 means every check passed.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import http.cookiejar
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ATTACK = ROOT / "datasets" / "synthetic"
BENIGN = ATTACK / "benign"


class ApiError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body


class Client:
    """A cookie-session API client that sends the CSRF header like the browser does."""

    def __init__(self, base: str):
        if urllib.parse.urlsplit(base).scheme not in ("http", "https"):
            raise SystemExit("--base-url must start with http:// or https://")
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _csrf(self) -> str:
        return next((c.value for c in self.jar if c.name == "st_csrf"), "")

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        params: dict[str, Any] | None = None,
        files: dict[str, tuple[str, bytes]] | None = None,
        raw: bool = False,
    ) -> Any:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        headers = {}
        data = None
        if files:
            boundary = uuid.uuid4().hex
            parts = []
            for name, (filename, content) in files.items():
                parts.append(
                    f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
                    f'filename="{filename}"\r\nContent-Type: text/plain\r\n\r\n'.encode()
                    + content
                    + b"\r\n"
                )
            data = b"".join(parts) + f"--{boundary}--\r\n".encode()
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if method not in ("GET", "HEAD"):
            headers["X-CSRF-Token"] = self._csrf()
        req = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310
        try:
            # The scheme was checked in __init__ (http/https only).
            with self.opener.open(req, timeout=120) as resp:  # noqa: S310
                payload = resp.read()
                if raw:
                    return payload.decode("utf-8"), dict(resp.headers)
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as exc:
            raise ApiError(exc.code, exc.read().decode("utf-8", "replace")) from None

    def status_of(self, method: str, path: str, body: Any = None) -> int:
        try:
            self.request(method, path, body)
            return 200
        except ApiError as exc:
            return exc.status

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: Any = None, **kw: Any) -> Any:
        return self.request("POST", path, body, **kw)

    def patch(self, path: str, body: Any) -> Any:
        return self.request("PATCH", path, body)

    def login(self, username: str, password: str) -> dict[str, Any]:
        return self.post("/api/auth/login", {"username": username, "password": password})


@dataclass
class Report:
    results: list[tuple[str, str, bool, str]] = field(default_factory=list)

    def check(self, criterion: str, name: str, ok: bool, evidence: str) -> bool:
        self.results.append((criterion, name, ok, evidence))
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name}: {evidence}")
        return ok

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r[2])


def wait_for(fn, timeout: float, what: str, interval: float = 1.0) -> Any:
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(interval)
    raise TimeoutError(f"timed out after {timeout:.0f}s waiting for {what}")


def all_alerts(c: Client) -> list[dict[str, Any]]:
    items, before = [], None
    while True:
        page = c.get("/api/alerts", limit=200, before_id=before)
        items += page["items"]
        before = page["next_before_id"]
        if before is None:
            return items


def import_dataset(c: Client, folder: Path, truth: dict[str, Any], tag: str) -> list[dict]:
    jobs = []
    for name, fmt in truth["sources"].items():
        src = c.post(
            "/api/sources",
            {
                "name": f"acceptance-{tag}-{name}",
                "format": fmt,
                "timezone": truth["source_timezone"],
            },
        )
        up = c.post(
            f"/api/sources/{src['id']}/files", files={"file": (name, (folder / name).read_bytes())}
        )
        jobs.append(up["job"])
    final = ("completed", "completed_with_errors", "failed")

    def finished(job_id: int) -> dict[str, Any] | None:
        job = c.get(f"/api/jobs/{job_id}")
        return job if job["status"] in final else None

    return [wait_for(lambda j=j: finished(j["id"]), 300, f"import job {j['id']}") for j in jobs]


def detection_idle(c: Client, job_ids: set[int]) -> bool:
    runs = c.get("/api/detection/runs", limit=100)
    mine = [r for r in runs if r["job_id"] in job_ids]
    return len(mine) == len(job_ids) and all(r["status"] in ("completed", "failed") for r in mine)


def entity_of(alert: dict[str, Any]) -> str:
    ip = alert["source_ip"]
    return f"user={alert['username']}|ip={ip}" if alert["username"] else f"ip={ip}"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--base-url", default="http://localhost:8080")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--json", type=Path, help="also write the results to this JSON file")
    args = ap.parse_args()
    password = os.environ.get("ST_ACCEPTANCE_PASSWORD") or getpass.getpass(
        f"Password for {args.username}: "
    )
    run = uuid.uuid4().hex[:6]
    rep = Report()
    attack_truth = json.loads((ATTACK / "ground_truth.json").read_text())
    benign_truth = json.loads((BENIGN / "ground_truth.json").read_text())

    print("\n1-2. Setup: services are up")
    anon = Client(args.base_url)
    health = anon.get("/api/health")
    ready = anon.get("/api/ready")
    rep.check(
        "1, 2",
        "API and database",
        health["status"] == "ok" and ready["database"] == "ok",
        f"health={health['status']} version={health['version']} database={ready['database']}",
    )
    page, headers = anon.request("GET", "/", raw=True)
    rep.check(
        "1, 2",
        "Frontend served",
        "<title>SentinelTrace</title>" in page,
        f"CSP: {headers.get('Content-Security-Policy', 'missing')[:60]}…",
    )

    print("\n3. Authentication and permissions")
    admin = Client(args.base_url)
    me = admin.login(args.username, password)
    rep.check(
        "3", "Admin login", me["user"]["role"] == "admin", f"signed in as {me['user']['username']}"
    )
    existing = [a for a in all_alerts(admin) if a["source_ip"] in attack_truth["attacker_ips"]]
    if existing:
        print(
            f"\nThis instance already has {len(existing)} alert(s) for the dataset's attacker IPs."
        )
        print("Run the acceptance check on a fresh installation (e.g. `docker compose down -v`).")
        return 2
    pw = f"Acceptance-{uuid.uuid4().hex}"
    for role in ("viewer", "analyst"):
        admin.post("/api/users", {"username": f"acc.{role}.{run}", "password": pw, "role": role})
    viewer, analyst = Client(args.base_url), Client(args.base_url)
    viewer.login(f"acc.viewer.{run}", pw)
    analyst.login(f"acc.analyst.{run}", pw)
    checks = {
        "anonymous GET /api/alerts": anon.status_of("GET", "/api/alerts") == 401,
        "viewer GET /api/alerts": viewer.status_of("GET", "/api/alerts") == 200,
        "viewer GET /api/users": viewer.status_of("GET", "/api/users") == 403,
        "viewer POST /api/sources": viewer.status_of(
            "POST", "/api/sources", {"name": "x", "format": "auto"}
        )
        == 403,
        "viewer GET /api/alerts/export": viewer.status_of("GET", "/api/alerts/export") == 403,
        "analyst GET /api/audit": analyst.status_of("GET", "/api/audit") == 403,
        "analyst GET /api/admin/system": analyst.status_of("GET", "/api/admin/system") == 403,
    }
    rep.check(
        "3",
        "Role-based access",
        all(checks.values()),
        ", ".join(f"{k}: {'ok' if v else 'WRONG'}" for k, v in checks.items()),
    )
    temp = Client(args.base_url)
    temp.login(f"acc.viewer.{run}", pw)
    temp.post("/api/auth/logout")
    rep.check(
        "3",
        "Logout invalidates the session",
        temp.status_of("GET", "/api/auth/me") == 401,
        "GET /api/auth/me after logout returned 401",
    )

    print("\n4. Import and parse the synthetic attack dataset")
    jobs = import_dataset(analyst, ATTACK, attack_truth, f"attack-{run}")
    lines = {
        n: sum(1 for _ in (ATTACK / n).open(encoding="utf-8")) for n in attack_truth["sources"]
    }
    rep.check("4", "All files parsed",
              all(j["status"] == "completed" and j["rejected_count"] == 0 for j in jobs)
              and sum(j["parsed_count"] for j in jobs) == sum(lines.values()),
              "; ".join(f"{j['filename']}: {j['status']}, {j['parsed_count']} parsed, "
                        f"{j['rejected_count']} rejected" for j in jobs))  # fmt: skip
    dup = analyst.status_of("POST", f"/api/sources/{jobs[0]['source_id']}/files")
    try:
        analyst.post(
            f"/api/sources/{jobs[0]['source_id']}/files",
            files={"file": ("again.log", (ATTACK / jobs[0]["filename"]).read_bytes())},
        )
        dup = 200
    except ApiError as exc:
        dup = exc.status
    rep.check("4", "Duplicate import refused", dup == 409, f"re-upload returned {dup}")

    print("\n5. Known suspicious patterns raise the expected evidence-backed alerts")
    wait_for(lambda: detection_idle(admin, {j["id"] for j in jobs}), 300, "detection")
    alerts = [admin.get(f"/api/alerts/{a['id']}") for a in all_alerts(admin)
              if a["source_ip"] in attack_truth["attacker_ips"] + attack_truth["benign_ips"]
              or a["username"]]  # fmt: skip
    expected = {
        (a["rule_id"], a["entity"], a["bucket_start"][:19]) for a in attack_truth["expected_alerts"]
    }
    produced = {(a["rule_id"], entity_of(a), a["bucket_start"][:19]) for a in alerts}
    missing, unexpected = expected - produced, produced - expected
    rep.check(
        "5",
        "Alerts match ground truth",
        not missing and not unexpected,
        f"{len(expected & produced)}/{len(expected)} expected alerts, "
        f"missing={sorted(missing)}, unexpected={sorted(unexpected)}",
    )
    evidence_ok = []
    for a in alerts:
        ev = admin.get(f"/api/alerts/{a['id']}/evidence", limit=5)
        evidence_ok.append(
            ev["total_linked"] > 0
            and all(i["raw_line"] for i in ev["items"])
            and a["reason"]
            and a["confidence_reason"]
            and a["recommended_steps"]
        )
    rep.check(
        "5",
        "Every alert has evidence and an explanation",
        all(evidence_ok) and bool(alerts),
        f"{sum(evidence_ok)}/{len(alerts)} alerts with original log lines, reason, "
        "confidence explanation and next steps",
    )
    rep.check(
        "5",
        "Alerts are worded as indicators",
        all("not" in a["reason"].lower() or "indicator" in a["reason"].lower() for a in alerts),
        "every reason states it is an indicator / does not confirm compromise",
    )

    print("\n6. Normal traffic does not trigger every rule")
    before = {a["id"] for a in all_alerts(admin)}
    bjobs = import_dataset(analyst, BENIGN, benign_truth, f"benign-{run}")
    wait_for(lambda: detection_idle(admin, {j["id"] for j in bjobs}), 300, "detection (benign)")
    new = [a for a in all_alerts(admin) if a["id"] not in before]
    rep.check(
        "6",
        "Benign-only dataset raises no alerts",
        not new and all(j["status"] == "completed" for j in bjobs),
        f"{sum(j['parsed_count'] for j in bjobs)} benign events imported, {len(new)} new alerts",
    )
    fired = {a["rule_id"] for a in alerts}
    rep.check(
        "6",
        "Benign entities in the attack dataset not alerted",
        not {a["source_ip"] for a in alerts} & set(attack_truth["benign_ips"]),
        f"{len(attack_truth['benign_ips'])} benign IPs, 0 alerted; rules fired: {len(fired)}",
    )

    print("\n7. Alerts can be investigated, updated and persisted")
    target = next(a for a in alerts if a["rule_id"] == "ST-WEB-001")
    analyst_me = analyst.get("/api/auth/me")["user"]
    analyst.patch(
        f"/api/alerts/{target['id']}",
        {"status": "investigating", "assigned_to": analyst_me["id"], "note": "acceptance"},
    )
    analyst.post(
        f"/api/alerts/{target['id']}/notes", {"kind": "action", "body": f"acceptance {run}"}
    )
    inc = analyst.post(
        "/api/incidents", {"title": f"Acceptance {run}", "alert_ids": [target["id"]]}
    )
    analyst.post(f"/api/incidents/{inc['id']}/notes", {"kind": "note", "body": "reviewed"})
    fresh = Client(args.base_url)
    fresh.login(args.username, password)
    after = fresh.get(f"/api/alerts/{target['id']}")
    activity = fresh.get(f"/api/alerts/{target['id']}/activity")
    incident = fresh.get(f"/api/incidents/{inc['id']}")
    rep.check("7", "Changes persist (read back in a new session)",
              after["status"] == "investigating" and after["assignee"] == analyst_me["username"]
              and any(n["body"] == f"acceptance {run}" for n in activity["notes"])
              and [a["id"] for a in incident["alerts"]] == [target["id"]],
              f"alert #{target['id']} investigating, owner {after['assignee']}, "
              f"{len(activity['notes'])} note(s), incident #{inc['id']} with "
              f"{len(incident['timeline'])} timeline entries")  # fmt: skip
    actions = {
        e["action"]
        for e in fresh.get("/api/audit", target_type="alert", target_id=str(target["id"]))["items"]
    }
    rep.check(
        "7",
        "Changes are in the audit log",
        {"alert.status_change", "alert.assign", "alert.note"} <= actions,
        f"actions: {sorted(actions)}",
    )

    print("\n8. Dashboard figures match independent queries")
    dash = admin.get("/api/dashboard", range="all")
    explorer = admin.get("/api/events", with_count="true", limit=1)
    every = all_alerts(admin)
    by_sev = {
        s: sum(1 for a in every if a["severity"] == s)
        for s in ("low", "medium", "high", "critical")
    }
    dash_sev = {r["key"]: r["count"] for r in dash["alerts_by_severity"]}
    capped = explorer["count_capped"]
    rep.check(
        "8",
        "Total events = event explorer count",
        capped or dash["totals"]["events"] == explorer["count"],
        f"dashboard {dash['totals']['events']}, explorer {explorer['count']}"
        + (" (explorer count capped; compared up to the cap)" if capped else ""),
    )
    rep.check(
        "8",
        "Alerts by severity = alert queue",
        dash_sev == by_sev and dash["totals"]["alerts"] == len(every),
        f"dashboard {dash_sev}, queue {by_sev}, total {dash['totals']['alerts']} vs {len(every)}",
    )
    open_queue = sum(1 for a in every if a["status"] in ("new", "investigating"))
    rep.check(
        "8",
        "Open alerts = alert queue",
        dash["totals"]["open_alerts"] == open_queue,
        f"dashboard {dash['totals']['open_alerts']}, queue {open_queue}",
    )

    print("\n9. Exports contain the correct records")
    text, _ = analyst.request("GET", "/api/alerts/export", params={"format": "csv"}, raw=True)
    rows = list(csv.DictReader(io.StringIO(text)))
    rep.check(
        "9",
        "Alert CSV = alert queue",
        sorted(int(r["id"]) for r in rows) == sorted(a["id"] for a in every),
        f"{len(rows)} rows vs {len(every)} alerts",
    )
    ip = "203.0.113.40"
    text, _ = analyst.request(
        "GET", "/api/events/export", params={"format": "json", "source_ip": ip}, raw=True
    )
    exported = json.loads(text)
    listed = admin.get("/api/events", source_ip=ip, with_count="true", limit=1)["count"]
    rep.check(
        "9",
        "Event export = explorer filter",
        len(exported) == listed and all(e["source_ip"] == ip for e in exported),
        f"{len(exported)} exported vs {listed} in the explorer for {ip}",
    )
    md, _ = analyst.request("GET", f"/api/incidents/{inc['id']}/report", raw=True)
    rep.check(
        "9",
        "Incident report content",
        f"#{target['id']}" in md and "reviewed" in md,
        f"Markdown report has alert #{target['id']} and the incident note ({len(md)} chars)",
    )

    print(f"\n{len(rep.results) - rep.failed}/{len(rep.results)} checks passed.")
    if args.json:
        keys = ("criterion", "check", "passed", "evidence")
        rows = [dict(zip(keys, r, strict=True)) for r in rep.results]
        args.json.write_text(json.dumps(rows, indent=2))
    return 1 if rep.failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ApiError, TimeoutError) as exc:
        print(f"\nAcceptance check aborted: {exc}", file=sys.stderr)
        sys.exit(1)

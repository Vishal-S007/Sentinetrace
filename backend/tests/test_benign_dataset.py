"""False-positive check: 24 hours of legitimate-only traffic must raise no alerts.

Ingests datasets/synthetic/benign/* through the upload API and the worker functions,
runs the detection that ingestion queues, and expects zero alerts with default rules.
"""

import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app.detection.runs import claim_next_run, process_run
from app.ingestion.processor import claim_next_job, process_job
from app.models import Alert, ImportedFile
from tests.conftest import csrf_headers

DATASET = Path(__file__).resolve().parents[2] / "datasets" / "synthetic" / "benign"


@pytest.fixture
def truth():
    return json.loads((DATASET / "ground_truth.json").read_text())


@pytest.fixture
def ingested(logged_in, db, settings, tmp_path, truth):
    settings.storage_dir = tmp_path / "storage"
    c, _ = logged_in("analyst")
    h = csrf_headers(c)
    file_ids = []
    for name, fmt in truth["sources"].items():
        sid = c.post(
            "/api/sources",
            json={"name": f"benign-{name}", "format": fmt, "timezone": truth["source_timezone"]},
            headers=h,
        ).json()["id"]
        resp = c.post(
            f"/api/sources/{sid}/files",
            files={"file": (name, (DATASET / name).read_bytes())},
            headers=h,
        )
        assert resp.status_code == 201, resp.text
        file_ids.append(resp.json()["file"]["id"])
    ref = datetime.fromisoformat(truth["reference_time"])
    for f in db.scalars(select(ImportedFile).where(ImportedFile.id.in_(file_ids))).all():
        f.uploaded_at = ref  # pins syslog year inference
    db.flush()
    jobs = []
    while (job := claim_next_job(db)) is not None:
        jobs.append(process_job(db, job, settings))
    runs = []
    while (run := claim_next_run(db)) is not None:
        runs.append(process_run(db, run, settings))
    return {"jobs": jobs, "runs": runs}


def test_benign_dataset_ingests_cleanly(ingested, truth):
    jobs = ingested["jobs"]
    assert [j.status for j in jobs] == ["completed"] * 3
    assert sum(j.rejected_count for j in jobs) == 0
    assert sum(j.parsed_count for j in jobs) == sum(truth["lines"].values())
    assert [r.status for r in ingested["runs"]] == ["completed"] * 3


def test_benign_dataset_raises_no_alerts(ingested, db, truth):
    alerts = db.scalars(select(Alert)).all()
    by_rule = Counter(a.rule_id for a in alerts)
    detail = [(a.rule_id, a.title) for a in alerts]
    print(
        f"\nBenign dataset: {sum(truth['lines'].values())} events, alerts by rule: {dict(by_rule)}"
    )
    assert detail == truth["expected_alerts"], detail


def test_near_misses_are_just_under_the_thresholds(ingested, db, settings, truth):
    """Lowering two thresholds by a little makes exactly the near-miss entities alert,
    so the zero-alert result above is not trivially far from the limits."""
    from app.models import DetectionRule
    from tests.detection_helpers import detect

    for rule_id, change in (("ST-AUTH-001", {"threshold": 4}), ("ST-WEB-004", {"threshold": 270})):
        rule = db.get(DetectionRule, rule_id)
        rule.config = {**rule.config, **change}
    db.flush()
    start = datetime.fromisoformat(truth["start"])
    detect(db, settings, start=start, end=start + timedelta(hours=truth["hours"]))
    found = {(a.rule_id, a.username or str(a.source_ip)) for a in db.scalars(select(Alert)).all()}
    assert ("ST-AUTH-001", "dave") in found  # 4 typos in 5 minutes
    assert ("ST-WEB-004", "198.51.100.200") in found  # office NAT at ~280/minute
    assert {r for r, _ in found} <= {"ST-AUTH-001", "ST-WEB-004", "ST-CORR-001"}

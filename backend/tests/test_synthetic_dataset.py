"""End-to-end evaluation on the synthetic dataset with ground truth.

Ingests datasets/synthetic/* through the real upload API and worker functions, runs the
detection that ingestion queues, and compares alerts with ground_truth.json.
Run with `-s` to print the metrics.
"""

import json
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from app.detection.evaluate import evaluate, file_ids_by_name
from app.detection.runs import claim_next_run, process_run
from app.ingestion.processor import claim_next_job, process_job
from app.models import Alert, ImportedFile
from tests.conftest import csrf_headers

DATASET = Path(__file__).resolve().parents[2] / "datasets" / "synthetic"


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
            json={"name": f"synthetic-{name}", "format": fmt, "timezone": truth["source_timezone"]},
            headers=h,
        ).json()["id"]
        resp = c.post(
            f"/api/sources/{sid}/files",
            files={"file": (name, (DATASET / name).read_bytes())},
            headers=h,
        )
        assert resp.status_code == 201, resp.text
        file_ids.append(resp.json()["file"]["id"])
    # Pin the upload time so syslog year inference is the same whenever the test runs.
    ref = datetime.fromisoformat(truth["reference_time"])
    for f in db.scalars(select(ImportedFile).where(ImportedFile.id.in_(file_ids))).all():
        f.uploaded_at = ref
    db.flush()

    jobs = []
    while (job := claim_next_job(db)) is not None:
        jobs.append(process_job(db, job, settings))
    runs = []
    while (run := claim_next_run(db)) is not None:
        runs.append(process_run(db, run, settings))
    return {"jobs": jobs, "runs": runs, "file_ids": file_ids, "client": c}


def test_dataset_ingests_cleanly(ingested):
    jobs = ingested["jobs"]
    assert [j.status for j in jobs] == ["completed"] * 3
    assert sum(j.rejected_count for j in jobs) == 0
    assert sum(j.parsed_count for j in jobs) == 6331 + 81 + 208
    assert [r.status for r in ingested["runs"]] == ["completed"] * 3


def test_alerts_match_ground_truth_exactly(ingested, db, truth):
    m = evaluate(db, truth, file_ids_by_name(db, ingested["file_ids"]))
    print("\nSynthetic dataset metrics:", json.dumps(m.as_dict(), indent=2))
    assert m.missing == [] and m.unexpected == []
    assert (m.precision, m.recall) == (1.0, 1.0)
    assert m.benign_entities_alerted == 0 and m.false_positive_rate == 0.0
    assert m.evidence_precision == 1.0  # every evidence line is labelled malicious


def test_every_alert_has_evidence_and_explanation(ingested, db):
    for a in db.scalars(select(Alert)).all():
        assert a.event_count > 0 and a.reason and a.confidence_reason
        assert a.recommended_action and a.first_seen <= a.last_seen
        assert (
            "Indicator only" in a.reason or "not confirmation" in a.reason or "does not" in a.reason
        ), a.rule_id


def test_brute_force_with_success_is_high_confidence(ingested, db):
    a = db.scalar(select(Alert).where(Alert.rule_id == "ST-AUTH-002"))
    assert a.confidence == "high" and a.details["successful_logins"] == ["test"]
    assert len(a.details["targeted_users"]) == 8


def test_rerunning_detection_changes_nothing(ingested, db, settings):
    from app.detection.runs import enqueue_manual

    before = {(a.rule_id, a.group_key, a.event_count) for a in db.scalars(select(Alert))}
    run = enqueue_manual(db, None, None, None)
    db.flush()
    claim_next_run(db)
    process_run(db, run, settings)
    assert (run.alerts_created, run.alerts_updated) == (0, 0)
    assert {(a.rule_id, a.group_key, a.event_count) for a in db.scalars(select(Alert))} == before

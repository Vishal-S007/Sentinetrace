"""Engine behaviour: idempotency, order independence, grouping, analyst fields, runs."""

from datetime import timedelta

from alembic.script import ScriptDirectory
from sqlalchemy import func, select

from app.detection.registry import RULES
from app.detection.runs import claim_next_run, enqueue_manual, process_run
from app.models import AlertEvent, DetectionRule, DetectionRuleVersion, DetectionRun
from tests.conftest import alembic_config
from tests.detection_helpers import T0, EventFactory, alerts, detect

ATTACKER = "203.0.113.66"


def snapshot(db):
    out = []
    for a in alerts(db):
        ids = sorted(
            db.scalars(select(AlertEvent.event_id).where(AlertEvent.alert_id == a.id)).all()
        )
        out.append(
            (
                a.rule_id,
                a.group_key,
                a.event_count,
                a.first_seen,
                a.last_seen,
                a.confidence,
                a.title,
                a.reason,
                tuple(ids),
            )
        )
    return out


def attack_scenario(ev):
    for i in range(30):
        ev.add(i, source_ip=ATTACKER, http_status=404, path=f"/probe-{i}")
    ev.add(100, source_ip=ATTACKER, path="/item", query="id=1%20union%20select%201")
    ev.many(25, 200, 5, event_type="auth_failure", username="admin", source_ip=ATTACKER)
    ev.add(400, event_type="auth_success", username="admin", source_ip=ATTACKER)
    ev.many(300, 4000, 0.1, source_ip="192.0.2.9")  # burst in the next bucket
    ev.flush()


def test_detection_is_idempotent(db, settings):
    attack_scenario(EventFactory(db))
    first = detect(db, settings)
    before = snapshot(db)
    second = detect(db, settings)
    assert first.created == len(before) > 0
    assert (second.created, second.updated) == (0, 0) and second.unchanged == len(before)
    assert snapshot(db) == before


def test_results_independent_of_range_splitting(db, settings):
    attack_scenario(EventFactory(db))
    # Process the two buckets separately, in reverse order...
    detect(db, settings, T0 + timedelta(hours=1), T0 + timedelta(hours=1, minutes=59))
    detect(db, settings, T0, T0 + timedelta(minutes=59))
    split = snapshot(db)
    # ...then the whole range at once: nothing changes.
    stats = detect(db, settings)
    assert (stats.created, stats.updated) == (0, 0)
    assert snapshot(db) == split
    assert {a[0] for a in split} == {
        "ST-WEB-006",
        "ST-WEB-001",
        "ST-AUTH-001",
        "ST-AUTH-002",
        "ST-WEB-004",
        "ST-CORR-001",
    }


def test_one_alert_per_entity_per_bucket(db, settings):
    ev = EventFactory(db)
    for minute in range(0, 120, 2):  # failures for 2 hours
        ev.many(5, minute * 60, 1, event_type="auth_failure", username="bob", source_ip=ATTACKER)
    detect(db, settings, only=["ST-AUTH-001"])
    found = alerts(db, "ST-AUTH-001")
    assert len(found) == 2  # one per hourly bucket, not one per window
    assert sum(a.event_count for a in found) == 300


def test_new_events_update_existing_alert_and_keep_analyst_fields(db, settings):
    ev = EventFactory(db)
    ev.many(5, 0, 10, event_type="auth_failure", username="carol", source_ip=ATTACKER)
    detect(db, settings, only=["ST-AUTH-001"])
    [a] = alerts(db, "ST-AUTH-001")
    a.status = "investigating"
    db.flush()

    ev.many(5, 100, 10, event_type="auth_failure", username="carol", source_ip=ATTACKER)
    stats = detect(db, settings, only=["ST-AUTH-001"])
    db.refresh(a)
    assert stats.updated == 1 and a.event_count == 10
    assert a.status == "investigating"  # analyst decision preserved
    assert len(alerts(db, "ST-AUTH-001")) == 1


def test_disabled_rule_does_not_fire(db, settings):
    db.get(DetectionRule, "ST-WEB-004").enabled = False
    EventFactory(db).many(400, 0, 0.1, source_ip=ATTACKER)
    detect(db, settings)
    assert alerts(db, "ST-WEB-004") == []


def test_alert_records_rule_version_and_severity(db, settings):
    rule = db.get(DetectionRule, "ST-WEB-004")
    rule.version, rule.severity = 7, "critical"
    EventFactory(db).many(300, 0, 0.1, source_ip=ATTACKER)
    detect(db, settings, only=["ST-WEB-004"])
    [a] = alerts(db, "ST-WEB-004")
    assert (a.rule_version, a.severity) == (7, "critical")


def test_threshold_change_takes_effect_on_rerun(db, settings):
    EventFactory(db).many(100, 0, 0.1, source_ip=ATTACKER)
    detect(db, settings, only=["ST-WEB-004"])
    assert alerts(db, "ST-WEB-004") == []
    rule = db.get(DetectionRule, "ST-WEB-004")
    rule.config = {**rule.config, "threshold": 100}
    detect(db, settings, only=["ST-WEB-004"])
    assert len(alerts(db, "ST-WEB-004")) == 1


def test_evidence_links_carry_indicators(db, settings):
    ev = EventFactory(db)
    e = ev.add(0, source_ip=ATTACKER, path="/x", query="q=%3Cscript%3E")
    detect(db, settings, only=["ST-WEB-002"])
    link = db.scalar(select(AlertEvent).where(AlertEvent.event_id == e.id))
    assert link.indicator == "script_tag"


def test_long_entity_keys_are_hashed(db, settings):
    ev = EventFactory(db)
    ev.many(5, 0, 1, event_type="auth_failure", username="u" * 250, source_ip=ATTACKER)
    detect(db, settings, only=["ST-AUTH-001"])
    [a] = alerts(db, "ST-AUTH-001")
    assert a.group_key.startswith("h=") and len(a.group_key) < 255


# --- Runs ------------------------------------------------------------------------------------


def test_manual_run_over_all_events(db, settings):
    attack_scenario(EventFactory(db))
    run = enqueue_manual(db, None, None, None)
    db.flush()
    assert claim_next_run(db).id == run.id
    process_run(db, run, settings)
    assert run.status == "completed" and run.alerts_created == len(alerts(db))
    assert run.range_start is not None and run.range_end is not None


def test_run_failure_is_recorded(db, settings, monkeypatch):
    import app.detection.runs as runs

    def boom(*a, **k):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(runs, "run_detection", boom)
    EventFactory(db).add(0, source_ip=ATTACKER)
    run = enqueue_manual(db, None, None, None)
    db.flush()
    claim_next_run(db)
    process_run(db, run, settings)
    assert run.status == "failed" and "secret" not in run.error_message


def test_empty_database_run_completes(db, settings):
    run = enqueue_manual(db, None, None, None)
    db.flush()
    claim_next_run(db)
    process_run(db, run, settings)
    assert (run.status, run.alerts_created) == ("completed", 0)


# --- Seeds ------------------------------------------------------------------------------------


def test_seeded_rules_match_code_defaults(db):
    rows = {r.rule_id: r for r in db.scalars(select(DetectionRule)).all()}
    assert set(rows) == set(RULES)
    script = ScriptDirectory.from_config(alembic_config("postgresql+psycopg://x@y/z"))
    migration = script.get_revision("0003").module
    seeded = {r["rule_id"]: r for r in migration.SEED_RULES}
    for rule_id, cls in RULES.items():
        assert seeded[rule_id]["severity"] == cls.default_severity
        assert seeded[rule_id]["config"] == cls.default_config(), rule_id
    assert db.scalar(
        select(func.count())
        .select_from(DetectionRuleVersion)
        .where(DetectionRuleVersion.version == 1)
    ) == len(RULES)


def test_every_rule_has_metadata():
    for rule_id, cls in RULES.items():
        assert cls.name and cls.description and cls.category
        assert len(cls.recommended_steps) >= 3, rule_id
        assert cls.default_severity in ("low", "medium", "high", "critical")


def test_detection_runs_table_has_no_leftovers(db):
    assert db.scalar(select(func.count()).select_from(DetectionRun)) == 0

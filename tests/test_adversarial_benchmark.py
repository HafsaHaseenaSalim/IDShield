"""
IDShield — adversarial benchmark tests.

Covers the generator (adversarial_benchmark.py) and the runner
(run_adversarial_benchmark.py): determinism, isolation from the main
database, that labels/campaign metadata never reach FraudEngine, and that
the campaign/decision-quality analysis functions compute what they claim to.
"""

import csv
import os

import adversarial_benchmark as ab
import config
import database as db
import evaluate_dataset as ev
import run_adversarial_benchmark as rb


# ---------------------------------------------------------------------------
# Deterministic, reproducible generation
# ---------------------------------------------------------------------------

def test_generation_is_deterministic_for_a_fixed_seed():
    first = ab.build_dataset("easy")
    second = ab.build_dataset("easy")
    assert first == second


def test_easy_medium_hard_are_different_datasets():
    easy = ab.build_dataset("easy")
    medium = ab.build_dataset("medium")
    hard = ab.build_dataset("hard")
    assert easy != medium
    assert medium != hard
    assert len(hard) > len(easy)      # hard tier deliberately adds more cases


def test_generated_rows_are_shuffled_out_of_chronological_order():
    """Section 8: the file order must not already be chronological — that is
    exactly what evaluate_dataset.py's sort step is responsible for fixing."""
    rows = ab.build_dataset("medium")
    timestamps = [r["timestamp"] for r in rows if r["timestamp"]]
    assert timestamps != sorted(timestamps)


# ---------------------------------------------------------------------------
# Isolation from the main database and from training
# ---------------------------------------------------------------------------

def test_building_the_benchmark_dataset_does_not_touch_the_main_database():
    conn = db.get_db()
    before = conn.execute("SELECT COUNT(*) AS c FROM attempts").fetchone()["c"]
    conn.close()

    ab.build_dataset("easy")   # in-memory only: no conn is opened at all

    conn = db.get_db()
    after = conn.execute("SELECT COUNT(*) AS c FROM attempts").fetchone()["c"]
    conn.close()
    assert before == after


def test_running_the_evaluator_on_generated_rows_does_not_touch_main_database(tmp_path):
    rows = ab.build_dataset("easy")[:10]
    path = tmp_path / "sample.csv"
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ab.FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    conn = db.get_db()
    before_exists = os.path.exists(config.DATABASE_PATH)
    before_mtime = os.path.getmtime(config.DATABASE_PATH) if before_exists else None
    conn.close()

    records = ev.load_and_normalize(path)
    ev.run_evaluation(records, str(tmp_path))

    assert os.path.exists(config.DATABASE_PATH) == before_exists
    if before_exists:
        assert os.path.getmtime(config.DATABASE_PATH) == before_mtime


def test_adversarial_module_has_no_training_code_path():
    """Challenge data must never be added to training: this module imports
    neither ml_engine.train nor anything that writes to the trained model."""
    import inspect
    source = inspect.getsource(ab)
    assert "ml_engine" not in source
    assert ".train(" not in source


# ---------------------------------------------------------------------------
# Labels/campaign metadata never reach FraudEngine
# ---------------------------------------------------------------------------

def test_campaign_id_and_label_never_reach_the_engine_attempt(tmp_path):
    rows = ab.build_dataset("medium")
    attack_rows = [r for r in rows if r["campaign_id"]]
    assert attack_rows, "fixture assumption: at least one campaign in the medium tier"

    path = tmp_path / "data.csv"
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ab.FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    records = ev.load_and_normalize(path)
    for rec in records:
        if rec.error is not None:
            continue
        attempt = ev.build_attempt(rec)
        serialised = str(attempt)
        assert "campaign_id" not in attempt
        assert "attack_category" not in attempt
        assert "label" not in attempt
        # The literal campaign/attack-type strings this dataset uses must not
        # leak into the engine-bound dict either.
        for banned in ("CS-BURST", "SYN-CHAIN", "DOC-FRAUD", "CREDENTIAL_STUFFING",
                      "SYNTHETIC_IDENTITY", "DOCUMENT_FRAUD"):
            assert banned not in serialised


# ---------------------------------------------------------------------------
# Campaign metrics
# ---------------------------------------------------------------------------

class _FakeRecord:
    def __init__(self, timestamp):
        self.timestamp = timestamp


def test_campaign_metrics_counts_a_campaign_as_detected_on_its_first_flagged_event():
    import datetime
    t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    records = [
        _FakeRecord(t0),
        _FakeRecord(t0 + datetime.timedelta(seconds=30)),
        _FakeRecord(t0 + datetime.timedelta(seconds=60)),
    ]
    rows = [
        {"status": "OK", "decision": "ALLOW"},
        {"status": "OK", "decision": "STEP_UP"},     # detected on the 2nd event
        {"status": "OK", "decision": "BLOCK"},
    ]
    extras = [{"campaign_id": "CAMP-1"}] * 3
    metrics = rb.campaign_metrics(records, rows, extras)
    assert metrics["campaigns_total"] == 1
    assert metrics["campaigns_detected"] == 1
    assert metrics["campaign_detection_rate"] == 1.0
    assert metrics["median_events_to_detection"] == 2
    assert metrics["median_seconds_to_detection"] == 30.0


def test_campaign_metrics_does_not_require_the_first_event_to_be_flagged():
    """A campaign detected only on its last event still counts as detected —
    fraud systems accumulate evidence; the first event is not required."""
    import datetime
    t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    records = [_FakeRecord(t0), _FakeRecord(t0 + datetime.timedelta(seconds=5))]
    rows = [{"status": "OK", "decision": "ALLOW"}, {"status": "OK", "decision": "BLOCK"}]
    extras = [{"campaign_id": "CAMP-1"}] * 2
    metrics = rb.campaign_metrics(records, rows, extras)
    assert metrics["campaigns_detected"] == 1


def test_campaign_metrics_reports_undetected_campaigns():
    import datetime
    t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    records = [_FakeRecord(t0), _FakeRecord(t0)]
    rows = [{"status": "OK", "decision": "ALLOW"}, {"status": "OK", "decision": "ALLOW"}]
    extras = [{"campaign_id": "CAMP-1"}] * 2
    metrics = rb.campaign_metrics(records, rows, extras)
    assert metrics["campaigns_total"] == 1
    assert metrics["campaigns_detected"] == 0
    assert metrics["campaign_detection_rate"] == 0.0
    assert metrics["median_events_to_detection"] is None


def test_rows_without_a_campaign_id_are_excluded_from_campaign_metrics():
    records = [_FakeRecord(None)]
    rows = [{"status": "OK", "decision": "BLOCK"}]
    extras = [{"campaign_id": None}]
    metrics = rb.campaign_metrics(records, rows, extras)
    assert metrics["campaigns_total"] == 0
    assert metrics["campaign_detection_rate"] is None


# ---------------------------------------------------------------------------
# Decision breakdown / decision quality — legitimate vs. attack kept separate
# ---------------------------------------------------------------------------

class _LabelRecord:
    def __init__(self, label_is_fraud):
        self.label_is_fraud = label_is_fraud


def test_decision_quality_separates_legitimate_and_attack_outcomes():
    records = [
        _LabelRecord(True), _LabelRecord(True), _LabelRecord(False), _LabelRecord(False),
    ]
    rows = [
        {"status": "OK", "decision": "STEP_UP"},   # attack, detected
        {"status": "OK", "decision": "ALLOW"},      # attack, missed
        {"status": "OK", "decision": "ALLOW"},      # legit, clean
        {"status": "OK", "decision": "BLOCK"},       # legit, harmed
    ]
    quality = rb.decision_quality(records, rows)
    assert quality["attack_detection_rate"] == 0.5
    assert quality["attack_hard_block_rate"] == 0.0
    assert quality["legitimate_friction_rate"] == 0.0
    assert quality["legitimate_harm_rate"] == 0.5


def test_decision_breakdown_counts_by_class_and_by_truth():
    records = [_LabelRecord(True), _LabelRecord(False)]
    rows = [{"status": "OK", "decision": "BLOCK"}, {"status": "OK", "decision": "STEP_UP"}]
    breakdown = rb.decision_breakdown(records, rows)
    assert breakdown["overall"] == {"ALLOW": 0, "STEP_UP": 1, "BLOCK": 1}
    assert breakdown["attack"] == {"ALLOW": 0, "STEP_UP": 0, "BLOCK": 1}
    assert breakdown["legitimate"] == {"ALLOW": 0, "STEP_UP": 1, "BLOCK": 0}


# ---------------------------------------------------------------------------
# Row-level metrics — reused from evaluate_dataset.py, checked end-to-end
# ---------------------------------------------------------------------------

def test_easy_dataset_scores_end_to_end_with_valid_output():
    rows = ab.build_dataset("easy")
    assert any(r["label"] == "LEGITIMATE" for r in rows)
    assert any(r["label"] != "LEGITIMATE" for r in rows)

    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "easy.csv"
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=ab.FIELDNAMES)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        records = ev.load_and_normalize(path)
        scored = ev.run_evaluation(records, tmp)
        metrics = ev.compute_metrics(records, scored)

    assert metrics is not None
    assert metrics["labeled_records"] == len(rows)
    for row in scored:
        if row["status"] == "OK":
            assert 0 <= row["risk_score"] <= 100
            assert row["decision"] in ("ALLOW", "STEP_UP", "BLOCK")

"""
IDShield — external dataset evaluator tests.

These exercise evaluate_dataset.py in isolation from the Flask app. The two
properties that matter most for a competition judge's unseen data are tested
explicitly: no future event can influence an earlier one's score, and the
main demo database is never touched.
"""

import json
import os

import config
import database as db
import evaluate_dataset as ev


# ---------------------------------------------------------------------------
# Loading and format detection
# ---------------------------------------------------------------------------

def test_valid_csv_is_loaded_and_scored(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text(
        "user_ref,timestamp,ip_address,device_id,login_success\n"
        "A-1,2026-01-01 10:00:00,203.0.113.5,DEV-1,true\n"
        "A-2,2026-01-01 10:05:00,203.0.113.6,DEV-2,true\n",
        encoding="utf-8",
    )
    records = ev.load_and_normalize(path)
    assert len(records) == 2
    rows = ev.run_evaluation(records, str(tmp_path))
    assert len(rows) == 2
    assert all(row["status"] == "OK" for row in rows)


def test_valid_json_array_is_loaded_and_scored(tmp_path):
    path = tmp_path / "data.json"
    path.write_text(json.dumps([
        {"user_ref": "A-1", "timestamp": "2026-01-01T10:00:00Z", "ip_address": "203.0.113.5"},
        {"user_ref": "A-2", "timestamp": "2026-01-01T10:05:00Z", "ip_address": "203.0.113.6"},
    ]), encoding="utf-8")
    records = ev.load_and_normalize(path)
    rows = ev.run_evaluation(records, str(tmp_path))
    assert len(rows) == 2 and all(row["status"] == "OK" for row in rows)


def test_valid_jsonl_is_loaded_and_scored(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"user_ref": "A-1", "timestamp": "2026-01-01T10:00:00Z"}\n'
        '{"user_ref": "A-2", "timestamp": "2026-01-01T10:05:00Z"}\n',
        encoding="utf-8",
    )
    records = ev.load_and_normalize(path)
    rows = ev.run_evaluation(records, str(tmp_path))
    assert len(rows) == 2 and all(row["status"] == "OK" for row in rows)


def test_malformed_csv_is_rejected_cleanly(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")
    try:
        ev.load_and_normalize(path)
        assert False, "expected a DatasetError"
    except ev.DatasetError:
        pass


def test_malformed_json_is_rejected_cleanly(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json", encoding="utf-8")
    try:
        ev.load_and_normalize(path)
        assert False, "expected a DatasetError"
    except ev.DatasetError:
        pass


def test_unsupported_extension_is_rejected_cleanly(tmp_path):
    path = tmp_path / "data.txt"
    path.write_text("x", encoding="utf-8")
    try:
        ev.load_and_normalize(path)
        assert False, "expected a DatasetError"
    except ev.DatasetError:
        pass


def test_one_malformed_jsonl_line_does_not_abort_the_rest(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"user_ref": "A-1", "timestamp": "2026-01-01T10:00:00Z"}\n'
        'not json at all\n'
        '{"user_ref": "A-2", "timestamp": "2026-01-01T10:05:00Z"}\n',
        encoding="utf-8",
    )
    records = ev.load_and_normalize(path)
    assert len(records) == 3
    rows = ev.run_evaluation(records, str(tmp_path))
    statuses = [row["status"] for row in rows]
    assert statuses.count("OK") == 2
    assert statuses.count("ERROR") == 1


# ---------------------------------------------------------------------------
# Safe missing-data handling
# ---------------------------------------------------------------------------

def test_missing_optional_fields_do_not_prevent_scoring(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text("user_ref,timestamp\nA-1,2026-01-01 10:00:00\n", encoding="utf-8")
    records = ev.load_and_normalize(path)
    rows = ev.run_evaluation(records, str(tmp_path))
    assert rows[0]["status"] == "OK"


def test_missing_required_identifier_is_a_clean_error_row(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text("user_ref,timestamp\n,2026-01-01 10:00:00\n", encoding="utf-8")
    records = ev.load_and_normalize(path)
    assert records[0].error == "missing identity/account identifier"
    rows = ev.run_evaluation(records, str(tmp_path))
    assert rows[0]["status"] == "ERROR"
    assert "identifier" in rows[0]["error_reason"]


def test_null_and_empty_values_are_treated_as_missing():
    for value in (None, "", "null", "NaN", "n/a", "  "):
        assert ev._is_empty(value) is True
    assert ev._is_empty("real-value") is False


def test_one_bad_row_does_not_stop_the_batch(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text(
        "user_ref,timestamp\n"
        "A-1,2026-01-01 10:00:00\n"
        ",2026-01-01 10:01:00\n"
        "A-2,2026-01-01 10:02:00\n",
        encoding="utf-8",
    )
    records = ev.load_and_normalize(path)
    rows = ev.run_evaluation(records, str(tmp_path))
    assert [row["status"] for row in rows] == ["OK", "ERROR", "OK"]


# ---------------------------------------------------------------------------
# Aliases, booleans, timestamps
# ---------------------------------------------------------------------------

def test_alternate_column_names_map_to_canonical_fields():
    raw = {
        "user_id": "U-1", "ip": "1.2.3.4", "device": "D-1", "dob": "1990-01-01",
        "login_result": "success", "time": "2026-01-01 00:00:00", "mail": "a@b.com",
    }
    canonical = ev.extract_aliases(raw)
    assert canonical["user_ref"] == "U-1"
    assert canonical["ip_address"] == "1.2.3.4"
    assert canonical["device_id"] == "D-1"
    assert canonical["date_of_birth"] == "1990-01-01"
    assert canonical["login_success"] == "success"
    assert canonical["timestamp"] == "2026-01-01 00:00:00"
    assert canonical["email"] == "a@b.com"


def test_boolean_aliases_normalize_consistently():
    for value in ("true", "1", "yes", "success", "pass", "allowed", True, 1):
        assert ev.normalize_bool(value) is True, value
    for value in ("false", "0", "no", "failure", "fail", "blocked", False, 0):
        assert ev.normalize_bool(value) is False, value
    assert ev.normalize_bool("maybe") is None
    assert ev.normalize_bool(None) is None


def test_timestamp_formats_all_parse_to_the_same_instant():
    variants = [
        "2026-09-11 10:30:00",
        "2026-09-11T10:30:00",
        "2026-09-11T10:30:00Z",
        "2026-09-11T14:30:00+04:00",     # same instant, +4 offset
    ]
    parsed = [ev.parse_timestamp(v) for v in variants]
    assert all(p is not None for p in parsed)
    assert len(set(parsed)) == 1


def test_unix_timestamp_seconds_and_milliseconds():
    seconds = ev.parse_timestamp("1780000000")
    millis = ev.parse_timestamp("1780000000000")
    assert seconds is not None and millis is not None
    assert seconds == millis


def test_unparseable_timestamp_is_none_not_a_crash():
    assert ev.parse_timestamp("not-a-date") is None
    assert ev.parse_timestamp("") is None
    assert ev.parse_timestamp(None) is None


# ---------------------------------------------------------------------------
# Temporal correctness — the critical property
# ---------------------------------------------------------------------------

def test_out_of_order_file_rows_are_sorted_chronologically_before_scoring():
    later = ev.normalize_record({"user_ref": "A", "timestamp": "2026-01-01 10:05:00"}, 0)
    earlier = ev.normalize_record({"user_ref": "B", "timestamp": "2026-01-01 10:00:00"}, 1)
    ordered = ev.chronological_order([later, earlier])
    assert [r.identity for r in ordered] == ["B", "A"]


def test_future_events_cannot_influence_earlier_scores(tmp_path):
    """
    Ten failed logins from one IP (file rows 0-9, ascending timestamps) push
    that IP over the credential-stuffing velocity floor and get it flagged.
    Row 10 shares that IP but is timestamped BEFORE all of them, and is
    placed LAST in the file. If time order is respected, row 10 is scored
    first, before any of the stuffing traffic exists — so it must come back
    clean regardless of its position in the file.
    """
    lines = ["user_ref,timestamp,ip_address,login_success"]
    for i in range(10):
        lines.append("BOT-%d,2026-01-01 10:%02d:00,203.0.113.99,false" % (i, i + 1))
    lines.append("EARLY-CLEAN,2026-01-01 09:00:00,203.0.113.99,true")   # earliest event, last in file
    path = tmp_path / "data.csv"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    records = ev.load_and_normalize(path)
    rows = ev.run_evaluation(records, str(tmp_path))
    by_ref = {row["user_ref"]: row for row in rows}

    early = by_ref["EARLY-CLEAN"]
    assert early["status"] == "OK"
    assert "CREDENTIAL_STUFFING_BURST" not in early["top_reasons"]
    assert "IP_FLAGGED" not in early["top_reasons"]
    assert early["decision"] == "ALLOW"
    assert early["risk_score"] < 30


def test_document_reuse_only_sees_records_already_processed_in_time():
    """A document presented earlier in time is 'reuse' for a later identity,
    never the other way around, regardless of file order."""
    later = ev.normalize_record({
        "user_ref": "LATER", "timestamp": "2026-01-01 10:05:00", "document_hash": "sharedhash",
    }, 0)
    earlier = ev.normalize_record({
        "user_ref": "EARLIER", "timestamp": "2026-01-01 10:00:00", "document_hash": "sharedhash",
    }, 1)
    rows = ev.run_evaluation([later, earlier], ".")
    by_ref = {row["user_ref"]: row for row in rows}
    # LATER (scored second, in time order) sees EARLIER's document as reuse.
    assert "DOCUMENT_REUSE" in by_ref["LATER"]["top_reasons"]
    # EARLIER (scored first) could not have seen LATER's future submission.
    assert "DOCUMENT_REUSE" not in by_ref["EARLIER"]["top_reasons"]


# ---------------------------------------------------------------------------
# Database isolation
# ---------------------------------------------------------------------------

def test_evaluator_never_touches_the_main_database(tmp_path):
    conn = db.get_db()
    conn.close()
    before_exists = os.path.exists(config.DATABASE_PATH)
    before_mtime = os.path.getmtime(config.DATABASE_PATH) if before_exists else None

    path = tmp_path / "data.csv"
    path.write_text("user_ref,timestamp\nA-1,2026-01-01 10:00:00\n", encoding="utf-8")
    records = ev.load_and_normalize(path)
    ev.run_evaluation(records, str(tmp_path))

    assert os.path.exists(config.DATABASE_PATH) == before_exists
    if before_exists:
        assert os.path.getmtime(config.DATABASE_PATH) == before_mtime


# ---------------------------------------------------------------------------
# Attack classification and labels
# ---------------------------------------------------------------------------

def test_labels_never_reach_the_fraud_engine():
    rec = ev.normalize_record({
        "user_ref": "A", "timestamp": "2026-01-01 10:00:00", "label": "CREDENTIAL_STUFFING",
    }, 0)
    assert rec.label_category == "CREDENTIAL_STUFFING" and rec.label_is_fraud is True
    attempt = ev.build_attempt(rec)
    serialised = str(attempt)
    assert "CREDENTIAL_STUFFING" not in serialised
    assert "label" not in attempt


def test_interpret_label_recognises_legitimate_and_fraud_tokens():
    assert ev.interpret_label("legitimate") == ("LEGITIMATE", False)
    assert ev.interpret_label("0") == ("LEGITIMATE", False)
    assert ev.interpret_label("1") == ("FRAUD", True)
    assert ev.interpret_label("SYNTHETIC_IDENTITY") == ("SYNTHETIC_IDENTITY", True)
    assert ev.interpret_label("") == (None, None)
    assert ev.interpret_label(None) == (None, None)


def test_classify_attack_does_not_use_ground_truth():
    reasons = [{"rule": "CREDENTIAL_STUFFING_BURST", "points": 25, "description": "x", "layer": "RULE"}]
    assert ev.classify_attack(reasons, "BLOCK") == "CREDENTIAL_STUFFING"
    assert ev.classify_attack([], "ALLOW") == "LEGITIMATE"
    assert ev.classify_attack([], "STEP_UP") == "SUSPICIOUS"


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

class _FakeRecord:
    def __init__(self, label_is_fraud, label_category=None):
        self.label_is_fraud = label_is_fraud
        self.label_category = label_category


def test_metrics_are_correct_on_a_known_toy_dataset():
    records = [
        _FakeRecord(True, "CREDENTIAL_STUFFING"),   # detected (STEP_UP)   -> TP
        _FakeRecord(True, "CREDENTIAL_STUFFING"),   # missed (ALLOW)       -> FN
        _FakeRecord(False),                         # correctly allowed   -> TN
        _FakeRecord(False),                         # wrongly blocked     -> FP
    ]
    rows = [
        {"status": "OK", "decision": "STEP_UP", "risk_score": 40, "fraud_probability": 0.7},
        {"status": "OK", "decision": "ALLOW", "risk_score": 5, "fraud_probability": 0.1},
        {"status": "OK", "decision": "ALLOW", "risk_score": 2, "fraud_probability": 0.05},
        {"status": "OK", "decision": "BLOCK", "risk_score": 80, "fraud_probability": 0.9},
    ]
    metrics = ev.compute_metrics(records, rows)
    assert metrics["labeled_records"] == 4
    assert metrics["accuracy"] == 0.5
    assert metrics["precision"] == 0.5          # TP=1, FP=1
    assert metrics["recall"] == 0.5             # TP=1, FN=1
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["false_negative_rate"] == 0.5
    assert metrics["attack_detection_rate"] == 0.5
    assert metrics["legitimate_block_rate"] == 0.5
    assert metrics["per_attack_type_detection"]["CREDENTIAL_STUFFING"] == 0.5


def test_unlabeled_dataset_returns_no_metrics_and_claims_no_accuracy(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text(
        "user_ref,timestamp\nA-1,2026-01-01 10:00:00\nA-2,2026-01-01 10:05:00\n",
        encoding="utf-8",
    )
    records = ev.load_and_normalize(path)
    rows = ev.run_evaluation(records, str(tmp_path))
    assert ev.compute_metrics(records, rows) is None


def test_cli_end_to_end_writes_results_and_skips_metrics_when_unlabeled(tmp_path, monkeypatch):
    data = tmp_path / "data.csv"
    data.write_text(
        "user_ref,timestamp,ip_address\nA-1,2026-01-01 10:00:00,203.0.113.1\n"
        "A-2,2026-01-01 10:05:00,203.0.113.2\n",
        encoding="utf-8",
    )
    output = tmp_path / "results.csv"
    monkeypatch.chdir(tmp_path)
    code = ev.main([str(data), "--output", str(output)])
    assert code == 0
    assert output.exists()
    assert not (output.parent / "metrics.json").exists()


def test_cli_end_to_end_writes_metrics_when_labeled(tmp_path, monkeypatch):
    data = tmp_path / "data.csv"
    data.write_text(
        "user_ref,timestamp,label\n"
        "A-1,2026-01-01 10:00:00,legitimate\n"
        "A-2,2026-01-01 10:05:00,fraud\n",
        encoding="utf-8",
    )
    output = tmp_path / "results.csv"
    monkeypatch.chdir(tmp_path)
    code = ev.main([str(data), "--output", str(output)])
    assert code == 0
    metrics_path = output.parent / "metrics.json"
    assert metrics_path.exists()
    metrics = json.loads(metrics_path.read_text())
    assert "accuracy" in metrics and metrics["labeled_records"] == 2


# ---------------------------------------------------------------------------
# Document path safety
# ---------------------------------------------------------------------------

def test_document_path_outside_the_allowed_root_is_refused(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.jpg"
    outside.write_bytes(b"not a real image, just needs to exist")
    assert ev.resolve_safe_document_path("../outside.jpg", str(allowed)) is None
    assert ev.resolve_safe_document_path(str(outside), str(allowed)) is None


def test_document_path_inside_the_allowed_root_resolves(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    inside = allowed / "doc.jpg"
    inside.write_bytes(b"data")
    resolved = ev.resolve_safe_document_path("doc.jpg", str(allowed))
    assert resolved == os.path.realpath(str(inside))


def test_missing_document_file_does_not_crash_scoring(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text(
        "user_ref,timestamp,document_path\nA-1,2026-01-01 10:00:00,does-not-exist.jpg\n",
        encoding="utf-8",
    )
    records = ev.load_and_normalize(path)
    rows = ev.run_evaluation(records, str(tmp_path))
    assert rows[0]["status"] == "OK"


# ---------------------------------------------------------------------------
# Output invariants
# ---------------------------------------------------------------------------

def test_risk_score_always_in_0_100_and_decision_always_valid_on_sample_datasets():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "sample_datasets"
    for name in ("sample_unlabeled.csv", "sample_labeled.csv"):
        records = ev.load_and_normalize(root / name)
        rows = ev.run_evaluation(records, str(root))
        for row in rows:
            if row["status"] != "OK":
                continue
            assert 0 <= row["risk_score"] <= 100
            assert row["decision"] in ("ALLOW", "STEP_UP", "BLOCK")

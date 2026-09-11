"""
IDShield — external dataset evaluator.

Scores a CSV/JSON/JSONL dataset that did NOT come from our own simulator,
using the exact same FraudEngine the live app and seed.py use. No scoring
logic is duplicated here: this file only loads data, normalizes it onto the
engine's existing attempt schema, and drives FraudEngine.evaluate() in
strict chronological order against an isolated, disposable database - the
same "replay against empty history, insert only after scoring" pattern
seed.py already uses for its own independent evaluation replay
(see rescore_with_model() / evaluate_independent_replay()).

Guarantees:
  * Never touches database/fraud.db, config.UPLOAD_DIR or any other live
    application state. Everything happens against an in-memory SQLite
    connection and a disposable temp directory for ELA heatmaps.
  * Never lets a later (in time) record influence an earlier one's score.
  * Never lets a ground-truth label reach FraudEngine.
  * One bad row does not stop the batch, and no ordinary bad input produces
    a raw traceback.

Usage:
    python evaluate_dataset.py data.csv
    python evaluate_dataset.py data.json
    python evaluate_dataset.py data.jsonl
    python evaluate_dataset.py data.csv --output results.csv
    python evaluate_dataset.py data.csv --documents-dir sample_datasets/documents
"""

import argparse
import contextlib
import csv
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import config
import database as db
import forensics
import graph_engine
import ml_engine
from fraud_engine import FraudEngine, apply_post_decision_reputation


class DatasetError(Exception):
    """A problem with the dataset FILE itself (not one bad row)."""


# ---------------------------------------------------------------------------
# 1. Loading — format detected from the file extension
# ---------------------------------------------------------------------------

def load_raw_records(path):
    """Return a list of raw dicts (or malformed-line markers) in file order."""
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return _load_csv(path)
    if suffix == ".json":
        return _load_json(path)
    if suffix == ".jsonl":
        return _load_jsonl(path)
    raise DatasetError(
        "Unsupported file type %r. Use .csv, .json or .jsonl." % suffix)


def _load_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        try:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise DatasetError("CSV file has no header row.")
            rows = list(reader)
        except csv.Error as exc:
            raise DatasetError("Could not parse CSV: %s" % exc) from exc
    if not rows:
        raise DatasetError("CSV file has a header but no data rows.")
    return rows


def _load_json(path):
    with open(path, encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise DatasetError("Invalid JSON: %s" % exc) from exc
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        data = data["records"]
    if not isinstance(data, list):
        raise DatasetError("Expected a JSON array of records "
                           "(or an object with a top-level \"records\" array).")
    if not data:
        raise DatasetError("JSON file contains no records.")
    return data


class _MalformedLine:
    """Marks one unparseable JSONL line without aborting the whole file."""
    def __init__(self, line_number, reason):
        self.line_number = line_number
        self.reason = reason


def _load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                rows.append(json.loads(text))
            except json.JSONDecodeError as exc:
                rows.append(_MalformedLine(line_number, str(exc)))
    if not rows:
        raise DatasetError("JSONL file contains no records.")
    return rows


# ---------------------------------------------------------------------------
# 2. Column aliases — one mapping table, used in exactly one place
# ---------------------------------------------------------------------------

ALIASES = {
    "user_ref": ["user_ref", "user_id", "customer_id", "identity_id",
                "account", "account_id", "username", "claimed_user_ref"],
    "full_name": ["full_name", "name"],
    "date_of_birth": ["date_of_birth", "dob", "birth_date"],
    "nationality": ["nationality", "country"],
    "phone": ["phone", "phone_number", "mobile"],
    "address": ["address"],
    "email": ["email", "email_address", "mail"],
    "ip_address": ["ip_address", "ip", "source_ip", "client_ip"],
    "device_id": ["device_id", "device", "device_fingerprint"],
    "timestamp": ["timestamp", "time", "datetime", "event_time"],
    "login_success": ["login_success", "login_result", "success", "authentication_success"],
    "liveness_status": ["liveness_status", "liveness", "liveness_result"],
    "document_path": ["document_path", "document", "doc_path", "image_path"],
    "document_hash": ["document_hash", "doc_hash"],
    "document_phash": ["document_phash", "doc_phash", "phash"],
    "document_anomaly": ["document_anomaly", "ela_score", "anomaly_score"],
    "document_name": ["document_name", "name_on_document"],
    "label": ["label", "is_fraud", "fraud", "attack_type", "scenario"],
}

_EMPTY_TOKENS = {"", "null", "none", "nan", "n/a", "na"}


def _normalize_key(key):
    return re.sub(r"[\s\-]+", "_", str(key).strip().lower())


def _is_empty(value):
    if value is None:
        return True
    if isinstance(value, float) and value != value:      # NaN
        return True
    return str(value).strip().lower() in _EMPTY_TOKENS


def _clean_str(value):
    return None if _is_empty(value) else str(value).strip()


def _to_float(value):
    if _is_empty(value):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def extract_aliases(raw):
    """Map a raw record's (arbitrarily-named) columns onto canonical fields."""
    normalized_raw = {_normalize_key(k): v for k, v in raw.items()}
    canonical = {}
    for canonical_field, aliases in ALIASES.items():
        for alias in aliases:
            if alias in normalized_raw and not _is_empty(normalized_raw[alias]):
                canonical[canonical_field] = normalized_raw[alias]
                break
    return canonical


# ---------------------------------------------------------------------------
# 3. Boolean normalization
# ---------------------------------------------------------------------------

_BOOL_TRUE = {"true", "1", "yes", "y", "t", "success", "pass", "passed",
             "allow", "allowed", "ok"}
_BOOL_FALSE = {"false", "0", "no", "n", "f", "failure", "fail", "failed",
              "block", "blocked", "denied", "deny"}


def normalize_bool(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    text = str(value).strip().lower()
    if text in _BOOL_TRUE:
        return True
    if text in _BOOL_FALSE:
        return False
    return None


def _status_from_bool(value):
    if value is True:
        return "PASS"
    if value is False:
        return "FAIL"
    return "NOT_SUBMITTED"


# ---------------------------------------------------------------------------
# 4. Timestamp normalization — always timezone-aware UTC internally
# ---------------------------------------------------------------------------

_NUMERIC_RE = re.compile(r"-?\d+(\.\d+)?")


def _from_unix(value):
    try:
        value = float(value)
        # Heuristic: anything with a magnitude typical of millisecond epochs.
        if abs(value) > 1e12:
            value = value / 1000.0
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError, TypeError):
        return None


_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S", "%Y-%m-%d",
)


def parse_timestamp(raw):
    """Return a tz-aware UTC datetime, or None if the value is missing/unusable."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return _from_unix(raw)
    text = str(raw).strip()
    if not text:
        return None
    if _NUMERIC_RE.fullmatch(text):
        return _from_unix(text)

    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    dt = None
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        for fmt in _TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# 5. Label interpretation — kept entirely separate from the engine
# ---------------------------------------------------------------------------

_LABEL_FRAUD_TOKENS = {"1", "true", "yes", "y", "fraud", "attack", "malicious", "positive"}
_LABEL_LEGIT_TOKENS = {"0", "false", "no", "n", "legitimate", "legit",
                       "benign", "normal", "clean", "negative"}


def interpret_label(raw):
    """
    Returns (category, is_fraud) or (None, None) if no usable label was given.

    A recognised "legitimate" spelling or a recognised "fraud" boolean-style
    token is mapped directly. Anything else non-empty is treated as the NAME
    of an attack/scenario category, and — because it is not "legitimate" —
    counted as fraud. This is deliberately generic: it makes no assumption
    about which attack-type spellings a judge's dataset will use.
    """
    if _is_empty(raw):
        return None, None
    text = str(raw).strip()
    lowered = text.lower()
    if lowered in _LABEL_LEGIT_TOKENS:
        return "LEGITIMATE", False
    if lowered in _LABEL_FRAUD_TOKENS:
        return "FRAUD", True
    return text.upper(), True


# ---------------------------------------------------------------------------
# 6. Normalized record
# ---------------------------------------------------------------------------

@dataclass
class NormalizedRecord:
    record_id: int
    identity: Optional[str] = None
    timestamp: Optional[datetime] = None
    fields: dict = field(default_factory=dict)
    label_category: Optional[str] = None
    label_is_fraud: Optional[bool] = None
    error: Optional[str] = None


def normalize_record(raw, record_id):
    if isinstance(raw, _MalformedLine):
        return NormalizedRecord(record_id=record_id,
                                error="line %d is not valid JSON (%s)"
                                      % (raw.line_number, raw.reason))
    if not isinstance(raw, dict):
        return NormalizedRecord(record_id=record_id,
                                error="record is not an object/row of fields")

    try:
        canonical = extract_aliases(raw)
        identity = _clean_str(canonical.get("user_ref"))
        if not identity:
            return NormalizedRecord(record_id=record_id,
                                    error="missing identity/account identifier")

        timestamp = parse_timestamp(canonical.get("timestamp"))
        fields = {
            "full_name": _clean_str(canonical.get("full_name")),
            "date_of_birth": _clean_str(canonical.get("date_of_birth")),
            "nationality": _clean_str(canonical.get("nationality")),
            "address": _clean_str(canonical.get("address")),
            "phone": _clean_str(canonical.get("phone")),
            "email": _clean_str(canonical.get("email")),
            "ip_address": _clean_str(canonical.get("ip_address")),
            "device_id": _clean_str(canonical.get("device_id")),
            "document_path": _clean_str(canonical.get("document_path")),
            "document_hash": _clean_str(canonical.get("document_hash")),
            "document_phash": _clean_str(canonical.get("document_phash")),
            "document_name": _clean_str(canonical.get("document_name")),
            "document_anomaly": _to_float(canonical.get("document_anomaly")),
            "login_status": _status_from_bool(normalize_bool(canonical.get("login_success"))),
            "liveness_status": _status_from_bool(normalize_bool(canonical.get("liveness_status"))),
            "had_login_field": canonical.get("login_success") is not None,
            "timestamp_db": timestamp.strftime("%Y-%m-%d %H:%M:%S") if timestamp else None,
        }
        label_category, label_is_fraud = interpret_label(canonical.get("label"))
        return NormalizedRecord(record_id=record_id, identity=identity, timestamp=timestamp,
                                fields=fields, label_category=label_category,
                                label_is_fraud=label_is_fraud)
    except Exception as exc:                    # noqa: BLE001 - one bad row must not abort the batch
        return NormalizedRecord(record_id=record_id,
                                error="could not be normalized (%s)" % type(exc).__name__)


def load_and_normalize(path):
    raw_records = load_raw_records(path)
    return [normalize_record(raw, i) for i, raw in enumerate(raw_records)]


# ---------------------------------------------------------------------------
# 7. Safe document handling — no path traversal, dataset works without files
# ---------------------------------------------------------------------------

def resolve_safe_document_path(raw_path, allowed_root):
    """Resolve a document reference, refusing anything outside allowed_root."""
    if not raw_path or not allowed_root:
        return None
    candidate = raw_path if os.path.isabs(raw_path) else os.path.join(allowed_root, raw_path)
    try:
        resolved = os.path.realpath(candidate)
        root = os.path.realpath(allowed_root)
    except OSError:
        return None
    if resolved != root and not resolved.startswith(root + os.sep):
        return None
    return resolved if os.path.isfile(resolved) else None


@contextlib.contextmanager
def _isolated_forensics_output_dir():
    """
    ELA analysis writes a heatmap PNG next to its input, defaulting to
    config.UPLOAD_DIR. Evaluating an external dataset must never write into
    the live app's uploads folder, so this redirects it to a disposable temp
    directory for the duration of the run and always restores it after.
    """
    original = config.UPLOAD_DIR
    temp_dir = tempfile.mkdtemp(prefix="idshield-eval-")
    config.UPLOAD_DIR = temp_dir
    try:
        yield temp_dir
    finally:
        config.UPLOAD_DIR = original
        shutil.rmtree(temp_dir, ignore_errors=True)


def build_forensics(rec_fields, documents_dir, doc_cache):
    """Real analysis from a file if one is safely referenced, else a synthetic
    forensic record built from whatever hash/score fields were supplied."""
    path = resolve_safe_document_path(rec_fields.get("document_path"), documents_dir)
    if path:
        try:
            result = forensics.analyse_document(path, cache=doc_cache)
            if result:
                return result
        except Exception:                        # noqa: BLE001
            pass

    doc_hash = rec_fields.get("document_hash")
    phash = rec_fields.get("document_phash")
    ela_score = rec_fields.get("document_anomaly")
    if not doc_hash and phash:
        doc_hash = "PHASH-%s" % phash             # best-effort dedup key only
    if not doc_hash and ela_score is None:
        return None                                # nothing at all to score on
    return {
        "doc_hash": doc_hash, "path": None, "phash": phash,
        "ela_score": ela_score, "ela_path": None, "metadata_flags": [],
    }


# ---------------------------------------------------------------------------
# 8. Attack classification — derived from the engine's OWN fired reasons,
#    never from a ground-truth label
# ---------------------------------------------------------------------------

ATTACK_CATEGORY_RULES = {
    "CREDENTIAL_STUFFING": {"CREDENTIAL_STUFFING_BURST", "VELOCITY_IP_MEDIUM",
                            "VELOCITY_ACCOUNT_SPREAD", "VELOCITY_FAILED_LOGINS",
                            "CREDENTIAL_FAILED"},
    "SYNTHETIC_IDENTITY": {"CROSS_RECORD_CLUSTER_LARGE", "CROSS_RECORD_CLUSTER_MEDIUM",
                           "CROSS_RECORD_CLUSTER_SMALL", "IMPLAUSIBLE_AGE",
                           "PHONE_NATIONALITY_MISMATCH", "DISPOSABLE_EMAIL",
                           "NAME_MISMATCH_DOCUMENT", "SEQUENTIAL_CONTACT_PATTERN",
                           "LINKED_TO_BLOCKED_STRONG", "LINKED_TO_BLOCKED_WEAK"},
    "DOCUMENT_FRAUD": {"DOCUMENT_ELA_ANOMALY", "DOCUMENT_METADATA_EDITOR",
                       "DOCUMENT_METADATA_MISSING", "DOCUMENT_REUSE"},
}


def classify_attack(reasons, decision):
    """
    The category whose rules contributed the most points wins ties are
    broken by CREDENTIAL_STUFFING > SYNTHETIC_IDENTITY > DOCUMENT_FRAUD,
    the dict order above, since Python dicts preserve insertion order).
    With no category-specific evidence: SUSPICIOUS if challenged/blocked,
    LEGITIMATE if allowed with nothing notable, UNKNOWN otherwise.
    """
    scores = {category: 0 for category in ATTACK_CATEGORY_RULES}
    for reason in reasons:
        for category, rules in ATTACK_CATEGORY_RULES.items():
            if reason["rule"] in rules:
                scores[category] += reason["points"]
    best_category = max(scores, key=lambda c: scores[c])
    if scores[best_category] > 0:
        return best_category
    if decision == config.DECISION_ALLOW:
        return "LEGITIMATE"
    if decision in (config.DECISION_STEP_UP, config.DECISION_BLOCK):
        return "SUSPICIOUS"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# 9. Evaluation loop — chronological, single pass, no future-state leakage
# ---------------------------------------------------------------------------

RESULT_FIELDNAMES = ["record_id", "user_ref", "normalized_timestamp", "risk_score",
                    "decision", "predicted_attack", "fraud_probability",
                    "rule_score", "top_reasons", "status", "error_reason"]


def _error_output(rec):
    return {
        "record_id": rec.record_id, "user_ref": rec.identity or "",
        "normalized_timestamp": rec.timestamp.isoformat() if rec.timestamp else "",
        "risk_score": "", "decision": "", "predicted_attack": "",
        "fraud_probability": "", "rule_score": "", "top_reasons": "",
        "status": "ERROR", "error_reason": rec.error or "could not be evaluated",
    }


def _ok_output(rec, result):
    reasons = sorted(result["reasons"], key=lambda r: r["points"], reverse=True)
    return {
        "record_id": rec.record_id, "user_ref": rec.identity,
        "normalized_timestamp": rec.timestamp.isoformat() if rec.timestamp else "",
        "risk_score": result["risk_score"], "decision": result["decision"],
        "predicted_attack": classify_attack(result["reasons"], result["decision"]),
        "fraud_probability": "" if result["ml_probability"] is None else result["ml_probability"],
        "rule_score": result["rule_points"],
        "top_reasons": ";".join(r["rule"] for r in reasons[:3]),
        "status": "OK", "error_reason": "",
    }


def build_attempt(rec):
    fields = rec.fields
    return {
        "claimed_user_ref": rec.identity,
        "full_name": fields.get("full_name"),
        "date_of_birth": fields.get("date_of_birth"),
        "nationality": fields.get("nationality"),
        "address": fields.get("address"),
        "phone": fields.get("phone"),
        "email": fields.get("email"),
        "ip_address": fields.get("ip_address"),
        "device_id": fields.get("device_id"),
        "timestamp": fields.get("timestamp_db"),
        "stage": config.STAGE_LOGIN if fields.get("had_login_field") else config.STAGE_ONBOARDING,
        "document_name": fields.get("document_name"),
        "liveness_status": fields.get("liveness_status", "NOT_SUBMITTED"),
        "login_status": fields.get("login_status", "NOT_SUBMITTED"),
        "scenario": "UNKNOWN",
        "attempt_ref": "EVAL-%06d" % rec.record_id,
    }


_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def chronological_order(records):
    """
    Valid records sorted by event time, earliest first — the order they must
    be scored in so a record can only ever be influenced by ones that truly
    happened before it, never by ones that merely appear earlier in the file.

    A record with no usable timestamp cannot be safely placed in time, so it
    sorts after every timestamped record (it must never appear to precede
    something), while ties (including "no timestamp") keep their original
    file order via a stable sort on record_id.
    """
    valid = [r for r in records if r.error is None]
    return sorted(valid, key=lambda r: (r.timestamp is None, r.timestamp or _EPOCH, r.record_id))


_AUTO_MODEL = object()


def run_evaluation(records, documents_dir, model=_AUTO_MODEL):
    """
    Score every valid record, strictly in chronological (event-time) order,
    against a fresh in-memory database and identity graph that starts empty.

    A record is scored BEFORE any of its own state (attempt row, document
    reuse count, IP/device reputation, graph edges) is persisted - exactly
    the ordering the live app and seed.py's own replay use - so a record can
    only ever be influenced by records that happened strictly before it.

    `model` defaults to loading the same trained model the live app uses.
    Pass an explicit ml_engine.RiskModel (e.g. RiskModel(estimator=None) for
    a rules-only run) to override that — this is what lets the adversarial
    benchmark compare rules-only against rules+ML without duplicating this
    function.
    """
    if model is _AUTO_MODEL:
        model = ml_engine.RiskModel.load()       # reuse the SAME trained model the app uses
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    db.init_db(conn)
    graph = graph_engine.IdentityGraph()
    engine = FraudEngine(conn, graph=graph, model=model)
    doc_cache = {}

    valid = chronological_order(records)

    outputs = {}
    with _isolated_forensics_output_dir():
        for rec in valid:
            try:
                forensic = build_forensics(rec.fields, documents_dir, doc_cache)
                if forensic and forensic.get("doc_hash"):
                    db.record_document(conn, forensic)

                attempt = build_attempt(rec)
                attempt["forensics"] = forensic
                attempt["document_hash"] = forensic["doc_hash"] if forensic else None
                attempt["document_status"] = "PASS" if forensic else "NOT_SUBMITTED"

                graph.add_attempt(attempt)
                result = engine.evaluate(attempt)
                db.insert_attempt(conn, result)
                apply_post_decision_reputation(conn, graph, result)
                outputs[rec.record_id] = _ok_output(rec, result)
            except Exception as exc:              # noqa: BLE001 - one bad row must not stop the batch
                rec.error = "could not be scored (%s)" % type(exc).__name__
                outputs[rec.record_id] = _error_output(rec)
    conn.close()

    for rec in records:
        if rec.error is not None and rec.record_id not in outputs:
            outputs[rec.record_id] = _error_output(rec)

    return [outputs[rec.record_id] for rec in records]


# ---------------------------------------------------------------------------
# 10. Label-aware metrics — computed strictly AFTER predictions are final
# ---------------------------------------------------------------------------

def compute_metrics(records, rows):
    """None if no record carries a usable ground-truth label."""
    labeled = [(rec, row) for rec, row in zip(records, rows)
              if row["status"] == "OK" and rec.label_is_fraud is not None]
    if not labeled:
        return None

    tp = sum(1 for rec, row in labeled if rec.label_is_fraud and row["decision"] != "ALLOW")
    fn = sum(1 for rec, row in labeled if rec.label_is_fraud and row["decision"] == "ALLOW")
    tn = sum(1 for rec, row in labeled if not rec.label_is_fraud and row["decision"] == "ALLOW")
    fp = sum(1 for rec, row in labeled if not rec.label_is_fraud and row["decision"] != "ALLOW")

    total = len(labeled)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)
         if precision and recall and (precision + recall) else None)
    false_positive_rate = fp / (fp + tn) if (fp + tn) else None
    false_negative_rate = fn / (fn + tp) if (fn + tp) else None

    legit_rows = [row for rec, row in labeled if not rec.label_is_fraud]
    attack_rows = [(rec, row) for rec, row in labeled if rec.label_is_fraud]
    legitimate_block_rate = (sum(1 for row in legit_rows if row["decision"] == "BLOCK")
                             / len(legit_rows)) if legit_rows else None
    legitimate_step_up_rate = (sum(1 for row in legit_rows if row["decision"] == "STEP_UP")
                               / len(legit_rows)) if legit_rows else None
    attack_detection_rate = (sum(1 for _, row in attack_rows if row["decision"] != "ALLOW")
                             / len(attack_rows)) if attack_rows else None

    per_category = defaultdict(lambda: {"total": 0, "detected": 0})
    for rec, row in attack_rows:
        category = rec.label_category or "UNKNOWN"
        per_category[category]["total"] += 1
        if row["decision"] != "ALLOW":
            per_category[category]["detected"] += 1
    per_attack_type_detection = {
        category: (counts["detected"] / counts["total"] if counts["total"] else None)
        for category, counts in per_category.items()
    }

    roc_auc = None
    truth = [1 if rec.label_is_fraud else 0 for rec, _ in labeled]
    if len(set(truth)) == 2:
        scores = [row["fraud_probability"] if row["fraud_probability"] != "" else row["risk_score"] / 100.0
                 for _, row in labeled]
        try:
            from sklearn.metrics import roc_auc_score
            roc_auc = float(roc_auc_score(truth, scores))
        except Exception:                        # noqa: BLE001
            roc_auc = None

    return {
        "records": len(records),
        "valid_records": sum(1 for row in rows if row["status"] == "OK"),
        "invalid_records": sum(1 for row in rows if row["status"] == "ERROR"),
        "labeled_records": total,
        "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1,
        "roc_auc": roc_auc,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "legitimate_block_rate": legitimate_block_rate,
        "legitimate_step_up_rate": legitimate_step_up_rate,
        "attack_detection_rate": attack_detection_rate,
        "per_attack_type_detection": per_attack_type_detection,
        "note": ("Computed from ground-truth labels supplied in the input dataset; "
                "labels were never passed to FraudEngine. These figures describe "
                "THIS dataset only and are not evidence of production performance."),
    }


# ---------------------------------------------------------------------------
# 11. Output
# ---------------------------------------------------------------------------

def write_results_csv(rows, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_metrics_json(metrics, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)


def print_summary(rows, metrics):
    total = len(rows)
    ok = sum(1 for row in rows if row["status"] == "OK")
    counts = defaultdict(int)
    for row in rows:
        if row["status"] == "OK":
            counts[row["decision"]] += 1
    print("Scored %d record(s): %d OK, %d ERROR" % (total, ok, total - ok))
    if ok:
        print("  ALLOW %d  STEP_UP %d  BLOCK %d"
             % (counts.get("ALLOW", 0), counts.get("STEP_UP", 0), counts.get("BLOCK", 0)))
    if metrics:
        print("Labeled records: %d  accuracy=%.3f  precision=%s  recall=%s  f1=%s"
             % (metrics["labeled_records"], metrics["accuracy"],
                _fmt(metrics["precision"]), _fmt(metrics["recall"]), _fmt(metrics["f1"])))
    else:
        print("No ground-truth label column detected: prediction statistics only, no accuracy claimed.")


def _fmt(value):
    return "n/a" if value is None else "%.3f" % value


# ---------------------------------------------------------------------------
# 12. CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Score an external CSV/JSON/JSONL dataset with the IDShield FraudEngine, "
                    "without running the Flask app or touching database/fraud.db.")
    parser.add_argument("input", help="Path to a .csv, .json or .jsonl dataset.")
    parser.add_argument("--output", default="results.csv",
                        help="Path for the results CSV (default: results.csv).")
    parser.add_argument("--documents-dir", default=None,
                        help="Directory that document_path values must resolve inside "
                            "(default: the dataset file's own directory).")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        print("Error: %s does not exist." % input_path, file=sys.stderr)
        return 1

    try:
        records = load_and_normalize(input_path)
    except DatasetError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError) as exc:
        print("Error: could not read %s (%s)" % (input_path, exc), file=sys.stderr)
        return 1

    documents_dir = os.path.realpath(args.documents_dir or str(input_path.resolve().parent))
    output_path = Path(args.output)

    rows = run_evaluation(records, documents_dir)
    write_results_csv(rows, output_path)
    print("Wrote %s" % output_path)

    metrics = compute_metrics(records, rows)
    if metrics:
        metrics_path = output_path.parent / "metrics.json"
        write_metrics_json(metrics, metrics_path)
        print("Wrote %s" % metrics_path)

    print_summary(rows, metrics)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
IDShield — adversarial benchmark runner.

Scores each adversarial_datasets/*.csv challenge set through the EXISTING
external evaluator (evaluate_dataset.py) — no FraudEngine logic is
duplicated here. This file only adds the analysis evaluate_dataset.py does
not already do on its own:

  * decisions broken down by class (ALLOW/STEP_UP/BLOCK), separately for
    legitimate and attack records;
  * detection vs. blocking, kept as separate figures rather than one
    combined number (section 13 of the brief);
  * campaign-level detection: a multi-event campaign counts as detected as
    soon as ANY of its events is challenged or blocked, not only the first;
  * a rules-only vs. rules+ML comparison, using the SAME trained model file
    the live app uses (no model is trained here).

Usage:
    python run_adversarial_benchmark.py
    python run_adversarial_benchmark.py --output benchmark_results/after_improvements.json
"""

import argparse
import csv
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

import config
import evaluate_dataset as ev
import ml_engine

BASE_DIR = Path(config.BASE_DIR)
DATASETS_DIR = BASE_DIR / "adversarial_datasets"
RESULTS_DIR = BASE_DIR / "benchmark_results"
BASELINE_PATH = RESULTS_DIR / "baseline.json"

DATASET_FILES = ["adversarial_easy.csv", "adversarial_medium.csv",
                 "adversarial_hard.csv", "adversarial_labeled.csv"]


def _dataset_key(filename):
    return filename.replace("adversarial_", "").replace(".csv", "")


def load_raw_extras(path):
    """campaign_id / attack_category are not part of evaluate_dataset.py's
    output schema, so they are read back from the source file directly, in
    the same file order evaluate_dataset.py assigns record_id from."""
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return [{"campaign_id": (row.get("campaign_id") or "").strip() or None,
                "attack_category": (row.get("attack_category") or "").strip() or None}
               for row in reader]


# ---------------------------------------------------------------------------
# Decision breakdown and detection/blocking separation (sections 11, 13, 19)
# ---------------------------------------------------------------------------

def decision_breakdown(records, rows):
    def empty():
        return {"ALLOW": 0, "STEP_UP": 0, "BLOCK": 0}
    overall, legitimate, attack = empty(), empty(), empty()
    for rec, row in zip(records, rows):
        if row["status"] != "OK":
            continue
        overall[row["decision"]] += 1
        if rec.label_is_fraud is True:
            attack[row["decision"]] += 1
        elif rec.label_is_fraud is False:
            legitimate[row["decision"]] += 1
    return {"overall": overall, "legitimate": legitimate, "attack": attack}


def decision_quality(records, rows):
    """
    Detection and blocking are reported separately on purpose (brief section
    13): a system that challenges 90% of attacks but hard-blocks only 10% of
    them is operating very differently from one that blocks 90% outright,
    and collapsing the two into one number would hide that.
    """
    legit = [row for rec, row in zip(records, rows)
            if row["status"] == "OK" and rec.label_is_fraud is False]
    attack = [row for rec, row in zip(records, rows)
             if row["status"] == "OK" and rec.label_is_fraud is True]

    def rate(rows_, predicate):
        return (sum(1 for row in rows_ if predicate(row)) / len(rows_)) if rows_ else None

    return {
        "attack_detection_rate": rate(attack, lambda r: r["decision"] in ("STEP_UP", "BLOCK")),
        "attack_hard_block_rate": rate(attack, lambda r: r["decision"] == "BLOCK"),
        "legitimate_friction_rate": rate(legit, lambda r: r["decision"] == "STEP_UP"),
        "legitimate_harm_rate": rate(legit, lambda r: r["decision"] == "BLOCK"),
    }


# ---------------------------------------------------------------------------
# Campaign-level detection (section 12)
# ---------------------------------------------------------------------------

def campaign_metrics(records, rows, extras):
    """
    A campaign counts as detected as soon as ANY member event is challenged
    or blocked — fraud systems accumulate evidence, so requiring the very
    first event of a campaign to be caught would understate a system that
    correctly recognises a pattern after a few events.
    """
    campaigns = {}
    for rec, row, extra in zip(records, rows, extras):
        campaign_id = extra.get("campaign_id")
        if not campaign_id or row["status"] != "OK":
            continue
        campaigns.setdefault(campaign_id, []).append((rec, row))

    epoch = datetime.min.replace(tzinfo=timezone.utc)
    events_to_detect, seconds_to_detect = [], []
    detected = 0
    for members in campaigns.values():
        members.sort(key=lambda pair: pair[0].timestamp or epoch)
        first_time = members[0][0].timestamp
        for position, (rec, row) in enumerate(members, start=1):
            if row["decision"] != "ALLOW":
                detected += 1
                events_to_detect.append(position)
                if first_time and rec.timestamp:
                    seconds_to_detect.append((rec.timestamp - first_time).total_seconds())
                break

    total = len(campaigns)
    return {
        "campaigns_total": total,
        "campaigns_detected": detected,
        "campaign_detection_rate": (detected / total) if total else None,
        "median_events_to_detection": statistics.median(events_to_detect) if events_to_detect else None,
        "median_seconds_to_detection": statistics.median(seconds_to_detect) if seconds_to_detect else None,
    }


# ---------------------------------------------------------------------------
# Running one dataset through one model configuration
# ---------------------------------------------------------------------------

def analyze(path, documents_dir, model):
    records = ev.load_and_normalize(path)
    rows = ev.run_evaluation(records, documents_dir, model=model)
    row_metrics = ev.compute_metrics(records, rows)
    extras = load_raw_extras(path)
    return {
        "records": len(records),
        "legitimate_records": sum(1 for r in records if r.label_is_fraud is False),
        "attack_records": sum(1 for r in records if r.label_is_fraud is True),
        "invalid_records": sum(1 for row in rows if row["status"] == "ERROR"),
        "row_metrics": row_metrics,
        "decision_breakdown": decision_breakdown(records, rows),
        "decision_quality": decision_quality(records, rows),
        "campaign_metrics": campaign_metrics(records, rows, extras),
    }


def build_report():
    documents_dir = str(DATASETS_DIR)
    trained_model = ml_engine.RiskModel.load()
    rules_only_model = ml_engine.RiskModel(estimator=None)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_trained": trained_model.is_trained,
        "note": ("Adversarial/unseen-data challenge sets, deliberately different from the "
                "simulator's own attack patterns (see adversarial_benchmark.py). These are "
                "synthetic demo metrics, not evidence of real-world performance."),
        "datasets": {},
    }
    for filename in DATASET_FILES:
        path = DATASETS_DIR / filename
        if not path.exists():
            print("Skipping %s (not found — run adversarial_benchmark.py first)" % filename, file=sys.stderr)
            continue
        key = _dataset_key(filename)
        report["datasets"][key] = {
            "rules_plus_ml": analyze(path, documents_dir, trained_model),
            "rules_only": analyze(path, documents_dir, rules_only_model),
        }
        print("  scored %s" % filename)
    return report


def print_summary(report):
    for key, bundle in report["datasets"].items():
        ml = bundle["rules_plus_ml"]
        rm = ml["row_metrics"] or {}
        dq = ml["decision_quality"]
        cm = ml["campaign_metrics"]
        print("\n[%s] %d records (%d legitimate, %d attack)"
             % (key, ml["records"], ml["legitimate_records"], ml["attack_records"]))
        print("  attack_detection_rate=%s  hard_block_rate=%s  legit_friction=%s  legit_harm=%s"
             % (_fmt(dq["attack_detection_rate"]), _fmt(dq["attack_hard_block_rate"]),
                _fmt(dq["legitimate_friction_rate"]), _fmt(dq["legitimate_harm_rate"])))
        if rm:
            per_type = rm.get("per_attack_type_detection") or {}
            print("  per-attack-type recall: %s"
                 % ", ".join("%s=%s" % (k, _fmt(v)) for k, v in sorted(per_type.items())))
        print("  campaign_detection_rate=%s (%d/%d), median_events_to_detect=%s"
             % (_fmt(cm["campaign_detection_rate"]), cm["campaigns_detected"], cm["campaigns_total"],
                cm["median_events_to_detection"]))


def _fmt(value):
    return "n/a" if value is None else "%.3f" % value


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the IDShield adversarial benchmark.")
    parser.add_argument("--output", default=str(BASELINE_PATH),
                        help="Where to write the JSON report (default: benchmark_results/baseline.json).")
    parser.add_argument("--force", action="store_true",
                        help="Allow overwriting an existing benchmark_results/baseline.json.")
    args = parser.parse_args(argv)

    output_path = Path(args.output)
    if output_path.resolve() == BASELINE_PATH.resolve() and BASELINE_PATH.exists() and not args.force:
        print("Error: %s already exists. The baseline is a fixed reference point and is "
             "not meant to be overwritten by later runs — pass --output for a new file "
             "(e.g. benchmark_results/after_improvements.json) or --force to replace it "
             "deliberately." % BASELINE_PATH, file=sys.stderr)
        return 1

    if not DATASETS_DIR.exists():
        print("Error: %s does not exist. Run adversarial_benchmark.py first." % DATASETS_DIR, file=sys.stderr)
        return 1

    report = build_report()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print("\nWrote %s" % output_path)
    print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
IDShield — one-command bootstrap.

    python seed.py            rebuild everything from scratch
    python seed.py --keep     add traffic to the existing database
    python seed.py --small    quick run, for a laptop in a hurry

Order matters and is deliberate:

  1. schema
  2. document pool
  3. calibrate the ELA threshold on that pool
  4. generate and score traffic with the RULE LAYER ONLY
  5. train the model on the resulting labelled data
  6. re-score every attempt with rules + model

Step 4 before step 5 is the bootstrap: the system has to be able to run, and
produce a labelled dataset, before any model exists. Step 6 then shows what the
model adds on top. A pipeline that cannot start without a trained model cannot
be deployed into a system that has never seen an attack.
"""

import argparse
import json
import os
import sys
import time
import tempfile
import secrets

import config
import database as db
import forensics
import graph_engine
import ml_engine
import simulator as sim
from fraud_engine import FraudEngine, apply_post_decision_reputation


def calibrate_ela(pool, verbose=True):
    """
    Fit the ELA threshold to the document pool instead of hard-coding it.

    Sweeps candidate thresholds and keeps the one with the best balanced
    accuracy on clean-vs-tampered. The fitted value and the achieved accuracy
    are written to models/ela_calibration.json so the number on the slide is
    traceable to a file rather than asserted.
    """
    clean = [forensics.error_level_analysis(p)[0] for p in pool.get("clean", [])]
    tampered = [forensics.error_level_analysis(p)[0] for p in pool.get("tampered", [])]
    if not clean or not tampered:
        return config.ELA_ANOMALY_THRESHOLD, None

    best = (0.0, config.ELA_ANOMALY_THRESHOLD)
    candidate = 0.0
    while candidate <= 40.0:
        true_negative = sum(1 for value in clean if value < candidate) / len(clean)
        true_positive = sum(1 for value in tampered if value >= candidate) / len(tampered)
        balanced = (true_negative + true_positive) / 2
        if balanced > best[0]:
            best = (balanced, candidate)
        candidate += 0.1

    accuracy, threshold = best
    calibration = {
        "threshold": round(threshold, 2),
        "balanced_accuracy": round(accuracy, 4),
        "n_clean": len(clean),
        "n_tampered": len(tampered),
        "clean_mean": round(sum(clean) / len(clean), 3),
        "tampered_mean": round(sum(tampered) / len(tampered), 3),
        "note": (
            "Fitted on the generated document pool. Error Level Analysis is an "
            "indicator, not proof of forgery: it is one input to a risk score "
            "with a step-up band, never a standalone verdict."
        ),
    }
    os.makedirs(config.MODEL_DIR, exist_ok=True)
    with open(config.ELA_CALIBRATION_PATH, "w") as handle:
        json.dump(calibration, handle, indent=2)

    config.ELA_ANOMALY_THRESHOLD = calibration["threshold"]
    if verbose:
        print("  ELA threshold calibrated to %.1f (balanced accuracy %.1f%%, "
              "clean mean %.1f vs tampered mean %.1f)"
              % (calibration["threshold"], accuracy * 100,
                 calibration["clean_mean"], calibration["tampered_mean"]))
    return calibration["threshold"], calibration


def rescore_with_model(conn, model, verbose=True):
    """
    Re-run every stored attempt through the engine with the model attached.

    The graph and reputation stores are rebuilt from scratch so the second pass
    sees the same world the first pass did, in the same order. Without that the
    two passes would not be comparable.
    """
    import sqlite3
    history = sqlite3.connect(":memory:")
    history.row_factory = sqlite3.Row
    db.init_db(history)
    graph = graph_engine.IdentityGraph()
    engine = FraudEngine(history, graph=graph, model=model)
    rows = conn.execute("SELECT * FROM attempts ORDER BY id ASC").fetchall()
    changed = 0
    try:
        for row in rows:
            attempt = dict(row)
            previous_decision = attempt.pop("decision")
            attempt.pop("initial_decision", None)
            forensic = None
            if attempt.get("document_hash"):
                doc = conn.execute("SELECT * FROM documents WHERE doc_hash=?",
                                   (attempt["document_hash"],)).fetchone()
                if doc:
                    forensic = dict(doc)
                    forensic["metadata_flags"] = json.loads(doc["metadata_flags"] or "[]")
            attempt["forensics"] = forensic
            graph.add_attempt(attempt)
            result = engine.evaluate(attempt)
            # Historical SQL sees only already replayed attempts. No current
            # attempt or future document reuse is visible to the engine.
            db.insert_attempt(history, result)
            apply_post_decision_reputation(history, graph, result)
            conn.execute(
                "UPDATE attempts SET rule_points=?, ml_probability=?, risk_score=?,"
                " decision=?, initial_decision=?, features=? WHERE id=?",
                (result["rule_points"], result["ml_probability"], result["risk_score"],
                 result["decision"], result["decision"], json.dumps(result["features"]), attempt["id"]))
            conn.execute("DELETE FROM reasons WHERE attempt_id=?", (attempt["id"],))
            for reason in result["reasons"]:
                conn.execute("INSERT INTO reasons (attempt_id, rule, description, points, layer) VALUES (?,?,?,?,?)",
                             (attempt["id"], reason["rule"], reason["description"], reason["points"], reason["layer"]))
            # Demo bootstrap replaces the original scoring events, so the
            # displayed audit and reasons describe the same assessment.
            conn.execute("DELETE FROM audit_log WHERE attempt_id=? AND event IN ('RISK_EVALUATED','ALLOW','STEP_UP','BLOCK')",
                         (attempt["id"],))
            db.log_event(conn, "RISK_EVALUATED", attempt["id"],
                         "score=%d decision=%s" % (result["risk_score"], result["decision"]), commit=False)
            changed += result["decision"] != previous_decision
        for table in ("flagged_ips", "flagged_devices"):
            conn.execute("DELETE FROM " + table)
            for row in history.execute("SELECT * FROM " + table):
                conn.execute("INSERT INTO " + table + " VALUES (?,?,?,?)", tuple(row))
        conn.commit()
    finally:
        history.close()
    if verbose:
        print("  replayed %d attempts against historical state (%d decisions changed)" % (len(rows), changed))
    return changed


def build_demo_documents(verbose=True):
    """
    Two documents reserved for the live demo: one genuine, one forged.

    They are deliberately NOT used by any simulated citizen. Uploading a
    document that already belongs to a simulated identity would (correctly)
    trigger the document-reuse rule, and a demo where the genuine example gets
    blocked for the wrong reason is a demo that argues against itself.
    """
    directory = os.path.join(config.BASE_DIR, "demo_documents")
    os.makedirs(directory, exist_ok=True)

    import docgen
    fields = {
        "full_name": "Demo Applicant", "date_of_birth": "1993-08-19",
        "nationality": "UAE", "id_number": "784-1993-4471902-6",
        "expiry": "2030-08-18", "altered_dob": "1999-01-04",
    }
    genuine = os.path.join(directory, "genuine_id.jpg")
    forged = os.path.join(directory, "forged_id.jpg")
    docgen.make_clean_document(fields, genuine, seed=777)
    docgen.make_tampered_document(fields, forged, seed=777,
                                  leave_editor_metadata=True)

    if verbose:
        for label, path in (("genuine", genuine), ("forged", forged)):
            score, _ = forensics.error_level_analysis(path)
            print("  demo_documents/%-15s ELA %.1f (%s)"
                  % (os.path.basename(path), score, label))
    return genuine, forged


def evaluate_independent_replay(model, metadata, training_conn, small=False):
    """Evaluate the frozen model with fresh documents and no training state."""
    evaluation_seed = config.RANDOM_SEED + 10000
    original_dir = config.ASSET_DOC_DIR
    with tempfile.TemporaryDirectory(prefix="idshield-evaluation-") as directory:
        evaluation_conn = db.get_db(os.path.join(directory, "evaluation.db"))
        try:
            db.init_db(evaluation_conn)
            config.ASSET_DOC_DIR = os.path.join(directory, "documents")
            pool = sim.ensure_document_pool(size=24 if small else 48, seed=evaluation_seed, verbose=False)
            graph = graph_engine.IdentityGraph()
            engine = FraudEngine(evaluation_conn, graph=graph, model=model)
            generator = sim.TrafficSimulator(evaluation_conn, engine=engine, graph=graph,
                                             seed=evaluation_seed, doc_pool=pool, namespace="EVAL")
            if small:
                generator.generate_mixed_traffic(n_legitimate=140, n_stuffing_campaigns=3,
                                                 n_rings=3, n_forged=20, verbose=False)
            else:
                generator.generate_mixed_traffic(verbose=False)
            training_hashes = {row[0] for row in training_conn.execute("SELECT doc_hash FROM documents")}
            evaluation_hashes = {row[0] for row in evaluation_conn.execute("SELECT doc_hash FROM documents")}
            if training_hashes & evaluation_hashes:
                raise ValueError("Evaluation documents overlap training documents.")
            metrics = ml_engine.evaluate(model, evaluation_conn, metadata, evaluation_seed)
            print("  independent evaluation: %d attempts; accuracy %.1f%%; AUC %s" % (
                metrics["n_test"], metrics["accuracy"] * 100,
                "n/a" if metrics["fraud_vs_legitimate_auc"] is None else "%.3f" % metrics["fraud_vs_legitimate_auc"]))
            return metrics
        finally:
            config.ASSET_DOC_DIR = original_dir
            evaluation_conn.close()


def main():
    parser = argparse.ArgumentParser(description="Bootstrap the IDShield demo.")
    parser.add_argument("--keep", action="store_true",
                        help="keep the existing database instead of rebuilding")
    parser.add_argument("--small", action="store_true",
                        help="generate a smaller dataset (faster)")
    parser.add_argument("--no-model", action="store_true",
                        help="skip model training (rule layer only)")
    args = parser.parse_args()
    if args.keep and args.no_model:
        parser.error("--keep preserves the current model; use --no-model with a fresh reset.")

    started = time.time()
    print("IDShield bootstrap")
    print("-" * 58)

    if not args.keep:
        db.reset_db(mark_building=True)
        print("[1/6] previous demo state cleared")
        for artifact in (config.MODEL_PATH, config.METRICS_PATH):
            if os.path.exists(artifact):
                os.remove(artifact)
        # Only generated upload files in the configured workspace upload directory.
        root = os.path.realpath(config.BASE_DIR)
        upload_dir = os.path.realpath(config.UPLOAD_DIR)
        if upload_dir != root and os.path.commonpath((root, upload_dir)) == root and os.path.isdir(upload_dir):
            for name in os.listdir(upload_dir):
                path = os.path.join(upload_dir, name)
                if os.path.isfile(path) and not os.path.islink(path):
                    os.remove(path)

    else:
        print("[1/6] keeping existing database")

    db.init_db()
    conn = db.get_db()
    conn.execute("INSERT OR REPLACE INTO runtime_state VALUES ('seed_status', 'building')")
    conn.commit()
    try:
        db.seed_demo_accounts(conn)
        print("      schema ready at %s" % os.path.relpath(config.DATABASE_PATH))
        print("      demo logins: citizen portal %s / %s -- analyst portal %s / %s"
              % (config.CUSTOMER_DEMO_EMAIL, config.CUSTOMER_DEMO_PASSWORD,
                 config.ANALYST_USERNAME, config.ANALYST_PASSWORD))

        print("[2/6] building document pool")
        pool = sim.ensure_document_pool(size=24 if args.small else 48)

        print("[3/6] document forensics")
        if not args.keep:
            calibrate_ela(pool)
        build_demo_documents()

        print("[4/6] generating traffic")
        graph = graph_engine.build_from_db(conn) if args.keep else graph_engine.IdentityGraph()
        engine = FraudEngine(conn, graph=graph, model=ml_engine.RiskModel.load() if args.keep else None)
        count = conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        generator = sim.TrafficSimulator(conn, engine=engine, graph=graph, doc_pool=pool,
                                         seed=config.RANDOM_SEED + count)

        if args.small:
            generator.generate_mixed_traffic(n_legitimate=140, n_stuffing_campaigns=3,
                                             n_rings=3, n_forged=20)
        else:
            generator.generate_mixed_traffic()

        if args.keep:
            print("[5/6] existing model and evaluation metrics preserved")
            print("[6/6] existing decisions and challenges preserved")
        elif args.no_model:
            for path in (config.MODEL_PATH, config.METRICS_PATH):
                if os.path.exists(path):
                    os.remove(path)
            print("[5/6] model training skipped (--no-model)")
            print("[6/6] nothing to re-score")
        else:
            print("[5/6] training the model")
            try:
                model, metrics = ml_engine.train(conn)
            except ValueError as exc:
                print("      skipped: %s" % exc)
                model = None
            if model is not None:
                print("[6/6] re-scoring every attempt with rules + model")
                rescore_with_model(conn, model)
                evaluate_independent_replay(model, metrics, conn, small=args.small)

    except BaseException:
        conn.rollback()
        conn.execute("INSERT OR REPLACE INTO runtime_state VALUES ('seed_status', 'failed')")
        conn.commit()
        raise
    finally:
        conn.close()
    conn = db.get_db()
    conn.execute("INSERT OR REPLACE INTO runtime_state VALUES ('seed_status', 'ready')")
    conn.execute("UPDATE runtime_state SET value=? WHERE key='generation'", (secrets.token_hex(16),))
    conn.commit()
    conn.close()
    print("-" * 58)
    print("done in %.1fs — start the app with:  python app.py" % (time.time() - started))
    return 0


if __name__ == "__main__":
    sys.exit(main())

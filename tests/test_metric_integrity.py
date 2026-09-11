"""
IDShield — dashboard metric integrity tests.

Covers two things found during final manual review of the analyst console's
"Independent synthetic evaluation" panel:

  1. The displayed per-class precision/recall/F1 must be independently
     reconstructible from the SAME confusion matrix shown next to it
     (ml_engine.metrics_from_confusion), rather than trusting a separately
     computed report to agree with it.
  2. No ground-truth label, scenario name or attack-type string is ever fed
     into the model's own feature vector - the classifier scores behaviour,
     not the label a citizen (or a fraud campaign) will eventually turn out
     to belong to.
"""

import sqlite3

import config
import database as db
import ml_engine


# ---------------------------------------------------------------------------
# Independent recomputation of precision / recall / F1 from a confusion matrix
# ---------------------------------------------------------------------------

def test_metrics_from_confusion_matches_hand_computed_values():
    """A small, deliberately different confusion matrix - proves the FORMULA
    is correct, not that a specific set of numbers was copied in."""
    labels = ["A", "B", "C"]
    matrix = [
        [8, 1, 1],   # actual A (support 10): 8 correct, 1 -> B, 1 -> C
        [0, 5, 0],   # actual B (support 5): 5 correct
        [2, 0, 3],   # actual C (support 5): 3 correct, 2 -> A
    ]
    per_class = ml_engine.metrics_from_confusion(matrix, labels)

    # A: TP=8, predicted-A total (column sum) = 8+0+2=10 -> FP=2, FN=10-8=2
    assert per_class["A"]["support"] == 10
    assert per_class["A"]["precision"] == 8 / 10
    assert per_class["A"]["recall"] == 8 / 10
    assert round(per_class["A"]["f1"], 6) == 0.8

    # B: TP=5, predicted-B total = 1+5+0=6 -> FP=1, FN=0
    assert per_class["B"]["support"] == 5
    assert per_class["B"]["precision"] == 5 / 6
    assert per_class["B"]["recall"] == 1.0

    # C: TP=3, predicted-C total = 1+0+3=4 -> FP=1, FN=2
    assert per_class["C"]["support"] == 5
    assert per_class["C"]["precision"] == 3 / 4
    assert per_class["C"]["recall"] == 3 / 5


def test_metrics_from_confusion_matches_the_reported_dashboard_matrix():
    """The exact confusion matrix from the manual-testing report, independently
    recomputed rather than trusted - confirms the displayed values were
    already mathematically correct before this task made any change."""
    labels = ["CREDENTIAL_STUFFING", "FORGED_DOCUMENT", "LEGITIMATE", "SYNTHETIC_IDENTITY"]
    matrix = [
        [123,   0,   0,  0],
        [  0,  56,  14,  0],
        [  0,  10, 510,  0],
        [  0,   0,   2, 35],
    ]
    per_class = ml_engine.metrics_from_confusion(matrix, labels)

    assert per_class["CREDENTIAL_STUFFING"] == {
        "precision": 1.0, "recall": 1.0, "f1": 1.0, "support": 123}

    forged = per_class["FORGED_DOCUMENT"]
    assert forged["support"] == 70
    assert round(forged["precision"], 2) == 0.85
    assert round(forged["recall"], 2) == 0.80
    assert round(forged["f1"], 2) == 0.82

    legitimate = per_class["LEGITIMATE"]
    assert legitimate["support"] == 520
    assert round(legitimate["precision"], 2) == 0.97
    assert round(legitimate["recall"], 2) == 0.98
    assert round(legitimate["f1"], 2) == 0.98

    synthetic = per_class["SYNTHETIC_IDENTITY"]
    assert synthetic["support"] == 37
    assert synthetic["precision"] == 1.0
    assert round(synthetic["recall"], 2) == 0.95
    assert round(synthetic["f1"], 2) == 0.97

    # 1. Confusion-matrix row sums equal displayed class support.
    supports = {"credential stuffing": 123, "forged document": 70, "legitimate": 520,
               "synthetic identity": 37}
    for i, label in enumerate(labels):
        assert sum(matrix[i]) == per_class[label]["support"]
        assert sum(matrix[i]) == supports[label.replace("_", " ").lower()]

    # 2. Total confusion-matrix count equals total evaluation records.
    assert sum(sum(row) for row in matrix) == 750


def test_zero_denominator_cases_are_handled_safely():
    labels = ["X", "Y"]
    matrix = [
        [0, 0],   # X: never actually occurs (support 0), and never predicted
        [3, 2],   # Y: support 5, but 3 of them were mispredicted as X
    ]
    per_class = ml_engine.metrics_from_confusion(matrix, labels)
    # X: undefined both ways (0/0) - must report 0.0, not raise or return NaN.
    assert per_class["X"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0}
    # Y: predicted-Y column total is 0+2=2, all of which were correct (TP=2,
    # FP=0) -> precision 1.0; only 2 of the 5 actual Y's were caught -> recall 0.4.
    assert per_class["Y"]["precision"] == 1.0
    assert per_class["Y"]["recall"] == 2 / 5


# ---------------------------------------------------------------------------
# Leakage checks: labels never reach the feature vector
# ---------------------------------------------------------------------------

def test_feature_names_contain_no_label_derived_fields():
    suspicious = {"scenario", "label", "attack_type", "decision",
                  "claimed_user_ref", "attempt_ref", "timestamp", "user_ref"}
    assert not (set(config.FEATURE_NAMES) & suspicious)


def test_build_dataset_never_puts_the_scenario_label_into_the_feature_vector():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    db.init_db(conn)
    db.insert_attempt(conn, {
        "attempt_ref": "LEAK-1", "timestamp": db.utcnow(), "claimed_user_ref": "X",
        "decision": "BLOCK", "scenario": "CREDENTIAL_STUFFING",
        "features": {name: 1.0 for name in config.FEATURE_NAMES},
    })
    X, y = ml_engine.build_dataset(conn)
    conn.close()
    assert X.shape == (1, len(config.FEATURE_NAMES))
    assert list(y) == ["CREDENTIAL_STUFFING"]


def test_evaluation_namespace_is_disjoint_from_training_namespace():
    """seed.py's independent evaluation replay uses namespace='EVAL', while
    ordinary training/demo traffic uses the default 'SIM' namespace - so
    identity references can never collide between the two populations."""
    import graph_engine
    import simulator as sim
    from fraud_engine import FraudEngine

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    db.init_db(conn)
    graph = graph_engine.IdentityGraph()
    engine = FraudEngine(conn, graph=graph)

    training_gen = sim.TrafficSimulator(conn, engine=engine, graph=graph, seed=1)
    eval_gen = sim.TrafficSimulator(conn, engine=engine, graph=graph, seed=1, namespace="EVAL")
    conn.close()

    assert training_gen.namespace == "SIM"
    assert eval_gen.namespace == "EVAL"
    training_ref = training_gen._identity(1)["user_ref"]
    eval_ref = eval_gen._identity(1)["user_ref"]
    assert training_ref != eval_ref
    assert training_ref.startswith("SIM-")
    assert eval_ref.startswith("EVAL-")


def test_seed_py_still_guards_against_document_overlap_between_train_and_eval():
    """Regression guard: evaluate_independent_replay() must keep asserting
    that no evaluation document hash was also seen during training, rather
    than silently trusting the two corpora are disjoint."""
    import inspect
    import seed
    source = inspect.getsource(seed.evaluate_independent_replay)
    assert "training_hashes" in source
    assert "evaluation_hashes" in source
    assert "raise ValueError" in source


def test_model_is_trained_before_the_independent_evaluation_runs():
    """seed.py's bootstrap order: train() on the training corpus first,
    independent replay of a FROZEN model second - never the reverse."""
    import inspect
    import seed
    source = inspect.getsource(seed.main)
    train_pos = source.index("ml_engine.train(conn)")
    eval_pos = source.index("evaluate_independent_replay(")
    assert train_pos < eval_pos

"""
IDShield — the model layer.

The existing Random Forest is trained on one synthetic replay and evaluated on
a separate replay with a different fixed seed. Calibration and model fitting
never use the evaluation corpus. Metrics describe synthetic traffic only.
"""

import json
import os

import numpy as np

import config


class RiskModel:
    """Wraps the classifier so the fraud engine never touches sklearn directly."""

    def __init__(self, estimator=None, feature_names=None, classes=None):
        self.estimator = estimator
        self.feature_names = feature_names or config.FEATURE_NAMES
        self.classes = classes or []

    # -- inference ---------------------------------------------------------

    def predict(self, features):
        """
        Return (probability_of_fraud, [(feature, importance), ...]).

        Probability of fraud is 1 - P(LEGITIMATE), which keeps the meaning
        stable no matter how many attack classes the model was trained on.
        """
        if self.estimator is None:
            return None, []

        vector = np.array(
            [[float(features.get(name, 0) or 0) for name in self.feature_names]]
        )
        probabilities = self.estimator.predict_proba(vector)[0]

        classes = list(self.estimator.classes_)
        if "LEGITIMATE" in classes:
            legitimate = probabilities[classes.index("LEGITIMATE")]
            fraud_probability = float(1.0 - legitimate)
        else:
            fraud_probability = float(probabilities.max())

        contributors = self._contributors(features)
        return fraud_probability, contributors

    def _contributors(self, features):
        """
        Which features drove this decision.

        Global feature importances weighted by the attempt's own non-zero
        values. This is an approximation, not SHAP: it says which signals were
        both present here and generally influential. The rule layer remains the
        authoritative explanation, and the UI labels this row as model context.
        """
        if self.estimator is None or not hasattr(self.estimator, "feature_importances_"):
            return []
        pairs = []
        for name, importance in zip(self.feature_names,
                                    self.estimator.feature_importances_):
            value = float(features.get(name, 0) or 0)
            if value > 0:
                pairs.append((name, float(importance) * value))
        pairs.sort(key=lambda item: item[1], reverse=True)
        return pairs[:5]

    # -- persistence -------------------------------------------------------

    def save(self, path=None):
        import joblib
        path = path or config.MODEL_PATH
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(
            {"estimator": self.estimator, "feature_names": self.feature_names},
            path,
        )
        return path

    @classmethod
    def load(cls, path=None):
        """Load a trained model, or return an inert model if none exists yet."""
        import joblib
        path = path or config.MODEL_PATH
        if not os.path.exists(path):
            return cls(estimator=None)
        try:
            payload = joblib.load(path)
            return cls(
                estimator=payload["estimator"],
                feature_names=payload.get("feature_names"),
            )
        except Exception:                   # noqa: BLE001
            return cls(estimator=None)

    @property
    def is_trained(self):
        return self.estimator is not None


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def build_dataset(conn):
    """Read stored feature vectors and ground-truth labels out of the database."""
    import database as db

    rows = db.get_training_rows(conn)
    X, y = [], []
    for row in rows:
        try:
            features = json.loads(row["features"] or "{}")
        except (TypeError, ValueError):
            continue
        if not features:
            continue
        X.append([float(features.get(name, 0) or 0) for name in config.FEATURE_NAMES])
        y.append(row["scenario"])
    return np.array(X), np.array(y)


def train(conn, seed=None, verbose=True):
    """Fit the existing Random Forest on the training corpus only.

    Evaluation is a separate seeded replay with disjoint documents and state;
    individual attempts from one campaign are never split across train/test.
    """
    from sklearn.ensemble import RandomForestClassifier
    seed = config.RANDOM_SEED if seed is None else seed
    X, y = build_dataset(conn)
    if len(X) < 50 or len(np.unique(y)) < 2:
        raise ValueError("Need at least 50 labelled attempts and two classes.")
    estimator = RandomForestClassifier(
        n_estimators=config.N_ESTIMATORS, random_state=seed,
        class_weight="balanced", min_samples_leaf=2)
    estimator.fit(X, y)
    model = RiskModel(estimator=estimator, feature_names=config.FEATURE_NAMES)
    model.save()
    metadata = {"n_train": len(X), "random_seed": seed}
    if verbose:
        print("  existing Random Forest trained on %d attempts" % len(X))
    return model, metadata


def evaluate(model, conn, training_metadata, evaluation_seed):
    """Report classifier metrics and actual engine decisions on unseen traffic."""
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
    X, y = build_dataset(conn)
    predictions = model.estimator.predict(X)
    probabilities = model.estimator.predict_proba(X)
    labels = list(model.estimator.classes_)
    report = classification_report(y, predictions, output_dict=True, zero_division=0)
    truth = (y != "LEGITIMATE").astype(int)
    auc = None
    if "LEGITIMATE" in labels and len(np.unique(truth)) == 2:
        auc = float(roc_auc_score(truth, 1 - probabilities[:, labels.index("LEGITIMATE")]))
    breakdown = [dict(row) for row in conn.execute(
        "SELECT scenario, initial_decision AS decision, COUNT(*) AS count FROM attempts "
        "WHERE scenario != 'UNKNOWN' GROUP BY scenario, initial_decision ORDER BY scenario, initial_decision")]
    legitimate = sum(row["count"] for row in breakdown if row["scenario"] == "LEGITIMATE")
    attacks = sum(row["count"] for row in breakdown if row["scenario"] != "LEGITIMATE")
    blocked = sum(row["count"] for row in breakdown if row["scenario"] == "LEGITIMATE" and row["decision"] == "BLOCK")
    stepped = sum(row["count"] for row in breakdown if row["scenario"] == "LEGITIMATE" and row["decision"] == "STEP_UP")
    detected = sum(row["count"] for row in breakdown if row["scenario"] != "LEGITIMATE" and row["decision"] in ("STEP_UP", "BLOCK"))
    metrics = {
        **training_metadata, "n_test": len(X), "n_total": training_metadata["n_train"] + len(X),
        "evaluation_seed": evaluation_seed, "accuracy": float(accuracy_score(y, predictions)),
        "fraud_vs_legitimate_auc": auc, "labels": labels,
        "confusion_matrix": confusion_matrix(y, predictions, labels=labels).tolist(),
        "per_class": {label: {"precision": report.get(label, {}).get("precision"),
                              "recall": report.get(label, {}).get("recall"),
                              "f1": report.get(label, {}).get("f1-score"),
                              "support": report.get(label, {}).get("support")} for label in labels},
        "feature_importances": dict(zip(model.feature_names, map(float, model.estimator.feature_importances_))),
        "engine": {"breakdown": breakdown,
                   "legitimate_block_rate": blocked / legitimate if legitimate else None,
                   "legitimate_step_up_rate": stepped / legitimate if legitimate else None,
                   "attack_detection_rate": detected / attacks if attacks else None},
        "methodology": "Independent synthetic replay using a different fixed seed, separate documents, identities and reputation/graph state. "
                       "The existing Random Forest and ELA threshold are frozen before evaluation. "
                       "Features are computed in arrival order using prior attempts only. "
                       "Classifier accuracy and engine step-up/block rates are separate measures. "
                       "This tests the same simulator distribution, not real-world performance.",
    }
    save_metrics(metrics)
    return metrics


def save_metrics(metrics, path=None):
    path = path or config.METRICS_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        json.dump(metrics, handle, indent=2)
    return path


def load_metrics(path=None):
    path = path or config.METRICS_PATH
    if not os.path.exists(path):
        return None
    try:
        with open(path) as handle:
            return json.load(handle)
    except (ValueError, OSError):
        return None

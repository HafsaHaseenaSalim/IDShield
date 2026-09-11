"""
IDShield — synthetic-identity detection iteration 2 tests.

Covers the multi-hop / weak-vs-strong cross-record calibration made in this
iteration (see benchmark_results/synthetic_iteration_2.json and
benchmark_results/failure_analysis.md for the benchmark evidence behind it).
Assertions are written against config.THRESHOLD_* and relative point
comparisons rather than hard-coded scores, so they exercise the actual
behaviour the rule is meant to have without re-encoding one specific tuning
as a magic number.
"""

import sqlite3

import config
import database as db
import graph_engine
from fraud_engine import FraudEngine


def _score(attempts):
    """Evaluate a list of attempts through a fresh engine/graph and return
    the LAST attempt's result (the one whose cluster is now fully formed)."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    db.init_db(conn)
    graph = graph_engine.IdentityGraph()
    engine = FraudEngine(conn, graph=graph)
    result = None
    for index, attempt in enumerate(attempts):
        attempt.setdefault("timestamp", "2026-01-01 00:%02d:00" % index)
        attempt.setdefault("attempt_ref", "TEST-%04d" % index)
        graph.add_attempt(attempt)
        result = engine.evaluate(attempt)
        db.insert_attempt(conn, result)
    conn.close()
    return result


def _rule_points(result, rule):
    return sum(r["points"] for r in result["reasons"] if r["rule"] == rule)


# ---------------------------------------------------------------------------
# Multi-hop synthetic rings (the pattern this iteration targets)
# ---------------------------------------------------------------------------

def test_multihop_chain_ring_scores_as_a_large_cluster_for_every_member():
    """A-B share a phone, B-C share a device, C-D share an address. No
    single member shares more than one attribute type, but the cluster as a
    whole is bound by three independent identifier types including a strong
    one (phone) — every member must be scored on that cluster-wide evidence."""
    attempts = [
        {"claimed_user_ref": "CHAIN-A", "phone": "+971500000001"},
        {"claimed_user_ref": "CHAIN-B", "phone": "+971500000001", "device_id": "DEV-CHAIN"},
        {"claimed_user_ref": "CHAIN-C", "device_id": "DEV-CHAIN", "address": "1 Chain Street"},
        {"claimed_user_ref": "CHAIN-D", "address": "1 Chain Street"},
    ]
    result = _score(attempts)
    assert _rule_points(result, "CROSS_RECORD_CLUSTER_LARGE") == config.POINTS["CROSS_RECORD_CLUSTER_LARGE"]
    assert result["risk_score"] >= config.THRESHOLD_STEP_UP
    assert result["decision"] in (config.DECISION_STEP_UP, config.DECISION_BLOCK)


def test_sparse_ring_with_multiple_binding_types_is_flagged():
    """Only some identities are directly connected, but the shared types
    (device + phone) span the whole ring once it is fully formed."""
    attempts = [
        {"claimed_user_ref": "SPARSE-D"},   # unconnected decoy, stays out of the cluster
        {"claimed_user_ref": "SPARSE-A", "device_id": "DEV-SPARSE"},
        {"claimed_user_ref": "SPARSE-B", "device_id": "DEV-SPARSE", "phone": "+971500000002"},
        {"claimed_user_ref": "SPARSE-C", "phone": "+971500000002"},
    ]
    result = _score(attempts)
    assert result["risk_score"] >= config.THRESHOLD_STEP_UP
    reasons = {r["rule"] for r in result["reasons"]}
    assert "CROSS_RECORD_CLUSTER_LARGE" in reasons or "CROSS_RECORD_CLUSTER_MEDIUM" in reasons


def test_strong_multi_attribute_cluster_scores_higher_than_single_weak_attribute():
    """Section 5: phone + address together must be treated as meaningfully
    stronger evidence than one shared device/address alone."""
    weak_attempts = [
        {"claimed_user_ref": "WEAK-%d" % i, "device_id": "DEV-WEAK"} for i in range(4)
    ]
    strong_attempts = [
        {"claimed_user_ref": "STRONG-%d" % i, "phone": "+971500000009",
         "address": "9 Strong Street"} for i in range(4)
    ]
    weak_result = _score(weak_attempts)
    strong_result = _score(strong_attempts)
    assert strong_result["risk_score"] > weak_result["risk_score"]
    assert _rule_points(weak_result, "CROSS_RECORD_CLUSTER_SMALL") == config.POINTS["CROSS_RECORD_CLUSTER_SMALL"]
    assert _rule_points(strong_result, "CROSS_RECORD_CLUSTER_LARGE") == config.POINTS["CROSS_RECORD_CLUSTER_LARGE"]


# ---------------------------------------------------------------------------
# Legitimate weak-only clusters must NOT escalate (section 7)
# ---------------------------------------------------------------------------

def test_household_sharing_only_an_ip_is_not_clustered_at_all():
    """IP is excluded from clustering entirely — a shared IP alone must
    never contribute any cross-record evidence."""
    attempts = [
        {"claimed_user_ref": "IPFAM-%d" % i, "ip_address": "198.51.100.10",
         "device_id": "DEV-%d" % i, "phone": "+97150000%04d" % i}
        for i in range(4)
    ]
    result = _score(attempts)
    reasons = {r["rule"] for r in result["reasons"]}
    assert not any(r.startswith("CROSS_RECORD_CLUSTER") for r in reasons)


def test_household_sharing_only_an_address_stays_below_step_up():
    attempts = [
        {"claimed_user_ref": "ADDRFAM-%d" % i, "address": "5 Family Row",
         "device_id": "DEV-%d" % i, "phone": "+97150001%04d" % i}
        for i in range(3)
    ]
    result = _score(attempts)
    assert _rule_points(result, "CROSS_RECORD_CLUSTER_SMALL") == config.POINTS["CROSS_RECORD_CLUSTER_SMALL"]
    assert result["decision"] == config.DECISION_ALLOW
    assert result["risk_score"] < config.THRESHOLD_STEP_UP


def test_workplace_sharing_one_ip_across_many_employees_is_not_flagged():
    attempts = [
        {"claimed_user_ref": "WORK-%d" % i, "ip_address": "198.51.100.55"}
        for i in range(8)
    ]
    result = _score(attempts)
    reasons = {r["rule"] for r in result["reasons"]}
    assert not any(r.startswith("CROSS_RECORD_CLUSTER") for r in reasons)
    assert result["decision"] == config.DECISION_ALLOW


def test_public_kiosk_device_shared_by_several_unrelated_visitors_stays_weak():
    """A device-only cluster, even with more members than the synthetic
    rings above, must stay in the SMALL/weak tier — size alone is not
    evidence (see fraud_engine.py's own rationale for this rule)."""
    attempts = [
        {"claimed_user_ref": "KIOSK-%d" % i, "device_id": "DEV-KIOSK"}
        for i in range(6)
    ]
    result = _score(attempts)
    reasons = {r["rule"] for r in result["reasons"]}
    assert "CROSS_RECORD_CLUSTER_SMALL" in reasons
    assert "CROSS_RECORD_CLUSTER_MEDIUM" not in reasons
    assert "CROSS_RECORD_CLUSTER_LARGE" not in reasons
    assert result["decision"] == config.DECISION_ALLOW


def test_device_only_cluster_does_not_reach_step_up_regardless_of_size():
    for size in (2, 4, 6, 10):
        attempts = [
            {"claimed_user_ref": "DEVONLY-%d-%d" % (size, i), "device_id": "DEV-SIZE-%d" % size}
            for i in range(size)
        ]
        result = _score(attempts)
        assert result["decision"] == config.DECISION_ALLOW, size
        assert result["risk_score"] < config.THRESHOLD_STEP_UP, size


# ---------------------------------------------------------------------------
# Explanation quality (section 8)
# ---------------------------------------------------------------------------

def test_cross_record_reason_names_the_binding_kinds_without_raw_pii():
    attempts = [
        {"claimed_user_ref": "EXPL-A", "phone": "+971500000077", "address": "77 Explain Ave"},
        {"claimed_user_ref": "EXPL-B", "phone": "+971500000077", "address": "77 Explain Ave"},
    ]
    result = _score(attempts)
    cluster_reasons = [r for r in result["reasons"] if r["rule"].startswith("CROSS_RECORD_CLUSTER")]
    assert cluster_reasons
    description = cluster_reasons[0]["description"]
    assert "+971500000077" not in description
    assert "77 Explain Ave" not in description
    assert "phone" in description and "address" in description


# ---------------------------------------------------------------------------
# General invariants
# ---------------------------------------------------------------------------

def test_score_stays_in_0_100_and_decision_stays_valid_for_large_rings():
    attempts = [
        {"claimed_user_ref": "BIG-%d" % i, "phone": "+971500000100",
         "address": "100 Big Street", "device_id": "DEV-BIG"}
        for i in range(12)
    ]
    result = _score(attempts)
    assert 0 <= result["risk_score"] <= 100
    assert result["decision"] in (config.DECISION_ALLOW, config.DECISION_STEP_UP, config.DECISION_BLOCK)

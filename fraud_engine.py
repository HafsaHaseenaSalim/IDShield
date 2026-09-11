"""
IDShield — the fraud engine.

Everything the verification API learns about an attempt arrives here, and one
risk score with a full reason chain comes out.

The engine has two layers:

  RULE LAYER  deterministic checks. Always runs, always explainable, and it is
              what produces the labelled dataset the model is later trained on.

  ML LAYER    a classifier over the features the rule layer already computed.
              Optional: if no model has been trained yet the engine degrades to
              rules only rather than failing. That matters because the very
              first run of the system has no model, and a fraud engine that
              cannot start without one is a fraud engine that cannot bootstrap.

Both layers feed one score, and the score maps to three outcomes. Policy floors
(config.POLICY_FLOORS) let a small number of hard controls override the blend,
because a statistical model should be allowed to escalate a decision but not to
quietly wave through something a deterministic control has already caught.
"""

import difflib
import re
from datetime import datetime, timezone

import config
import database as db
import graph_engine


class Reason:
    """One line of the explanation shown to the analyst."""

    __slots__ = ("rule", "description", "points", "layer")

    def __init__(self, rule, description, points, layer="RULE"):
        self.rule = rule
        self.description = description
        self.points = points
        self.layer = layer

    def as_dict(self):
        return {
            "rule": self.rule,
            "description": self.description,
            "points": self.points,
            "layer": self.layer,
        }


class FraudEngine:
    """
    Evaluates attempts. Holds the identity graph and (optionally) the model so
    neither has to be rebuilt per attempt.
    """

    def __init__(self, conn, graph=None, model=None, doc_cache=None):
        self.conn = conn
        self.graph = graph
        self.model = model
        self.doc_cache = doc_cache if doc_cache is not None else {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def evaluate(self, attempt):
        """
        Score one attempt.

        `attempt` is a plain dict describing what the citizen submitted plus the
        connection metadata. Returns the same dict enriched with the score, the
        decision, the reason chain and the feature vector, ready to persist.
        """
        reasons = []
        features = {name: 0 for name in config.FEATURE_NAMES}

        self._check_velocity(attempt, reasons, features)
        self._check_reputation(attempt, reasons, features)
        self._check_attributes(attempt, reasons, features)
        self._check_cross_records(attempt, reasons, features)
        self._check_document(attempt, reasons, features)
        self._check_verification_outcomes(attempt, reasons, features)

        rule_points = sum(reason.points for reason in reasons)

        ml_probability = None
        if self.model is not None:
            ml_probability, ml_reason = self._score_with_model(features)
            if ml_reason:
                reasons.append(ml_reason)

        score = self._combine(rule_points, ml_probability, reasons)
        decision = self.decide(score)

        attempt.update({
            "rule_points": rule_points,
            "ml_probability": ml_probability,
            "risk_score": score,
            "decision": decision,
            "reasons": [reason.as_dict() for reason in reasons],
            "features": features,
        })
        return attempt

    @staticmethod
    def decide(score):
        if score >= config.THRESHOLD_BLOCK:
            return config.DECISION_BLOCK
        if score >= config.THRESHOLD_STEP_UP:
            return config.DECISION_STEP_UP
        return config.DECISION_ALLOW

    # ------------------------------------------------------------------
    # Rule layer
    # ------------------------------------------------------------------

    def _check_velocity(self, attempt, reasons, features):
        """
        Credential stuffing shows up as rate, not as a bad password.

        Windows are measured relative to the attempt's own timestamp rather than
        wall-clock now(). That keeps a replayed dataset scoring identically on
        every run, which is what makes the demo reproducible.
        """
        ip = attempt.get("ip_address")
        timestamp = attempt.get("timestamp")
        if not ip or not timestamp:
            return

        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM attempts WHERE ip_address = ?"
            " AND timestamp <= ? AND timestamp >= datetime(?, ?)",
            (ip, timestamp, timestamp, "-%d seconds" % config.VELOCITY_WINDOW_SECONDS),
        ).fetchone()
        count = row["c"] if row else 0
        features["velocity_ip_count"] = count

        if count >= config.VELOCITY_IP_HIGH_COUNT:
            reasons.append(Reason(
                "CREDENTIAL_STUFFING_BURST",
                "%d attempts from this IP within %ds"
                % (count, config.VELOCITY_WINDOW_SECONDS),
                config.POINTS["VELOCITY_IP_HIGH"],
            ))
        elif count >= config.VELOCITY_IP_MEDIUM_COUNT:
            reasons.append(Reason(
                "VELOCITY_IP_MEDIUM",
                "%d attempts from this IP within %ds"
                % (count, config.VELOCITY_WINDOW_SECONDS),
                config.POINTS["VELOCITY_IP_MEDIUM"],
            ))

        spread_row = self.conn.execute(
            "SELECT COUNT(DISTINCT claimed_user_ref) AS c FROM attempts"
            " WHERE ip_address = ? AND timestamp <= ? AND timestamp >= datetime(?, ?)",
            (ip, timestamp, timestamp,
             "-%d seconds" % config.ACCOUNT_SPREAD_WINDOW_SECONDS),
        ).fetchone()
        spread = spread_row["c"] if spread_row else 0
        features["velocity_account_spread"] = spread

        if spread >= config.ACCOUNT_SPREAD_COUNT:
            reasons.append(Reason(
                "VELOCITY_ACCOUNT_SPREAD",
                "One IP targeted %d different accounts in %d minutes"
                % (spread, config.ACCOUNT_SPREAD_WINDOW_SECONDS // 60),
                config.POINTS["VELOCITY_ACCOUNT_SPREAD"],
            ))

        claimed = attempt.get("claimed_user_ref")
        if claimed:
            failed_row = self.conn.execute(
                "SELECT COUNT(*) AS c FROM attempts WHERE claimed_user_ref = ?"
                " AND login_status = 'FAIL' AND timestamp <= ?"
                " AND timestamp >= datetime(?, ?)",
                (claimed, timestamp, timestamp,
                 "-%d seconds" % config.FAILED_LOGIN_WINDOW_SECONDS),
            ).fetchone()
            failed = failed_row["c"] if failed_row else 0
            features["failed_login_count"] = failed
            if failed >= config.FAILED_LOGIN_COUNT:
                reasons.append(Reason(
                    "VELOCITY_FAILED_LOGINS",
                    "%d failed logins against this account in %d minutes"
                    % (failed, config.FAILED_LOGIN_WINDOW_SECONDS // 60),
                    config.POINTS["VELOCITY_FAILED_LOGINS"],
                ))

    def _check_reputation(self, attempt, reasons, features):
        flagged_ip = db.is_ip_flagged(self.conn, attempt.get("ip_address"))
        if flagged_ip:
            features["ip_flagged"] = 1
            reasons.append(Reason(
                "IP_FLAGGED",
                "IP previously involved in blocked attempts (%s)"
                % (flagged_ip["reason"] or "prior abuse"),
                config.POINTS["IP_FLAGGED"],
            ))

        flagged_device = db.is_device_flagged(self.conn, attempt.get("device_id"))
        if flagged_device:
            features["device_flagged"] = 1
            reasons.append(Reason(
                "DEVICE_FLAGGED",
                "Device previously involved in blocked attempts",
                config.POINTS["DEVICE_FLAGGED"],
            ))

        if self.graph is not None:
            count = self.graph.device_identity_count(attempt.get("device_id"))
            features["device_identity_count"] = count
            if count >= config.DEVICE_SHARED_IDENTITY_COUNT:
                reasons.append(Reason(
                    "DEVICE_SHARED_HIGH",
                    "Device has been used by %d different identities" % count,
                    config.POINTS["DEVICE_SHARED_HIGH"],
                ))

    def _check_attributes(self, attempt, reasons, features):
        """Plausibility of the identity taken on its own."""
        flags = 0

        age = self._age_from_dob(attempt.get("date_of_birth"), attempt.get("timestamp"))
        if age is not None and (age < 16 or age > 100):
            flags += 1
            reasons.append(Reason(
                "IMPLAUSIBLE_AGE",
                "Date of birth implies an age of %d" % age,
                config.POINTS["IMPLAUSIBLE_AGE"],
            ))

        # Nationality is not a residence, and a phone number is not proof of
        # either - an Indian national living in the UAE on a UAE number (or
        # keeping an Indian one) is completely ordinary. So this compares the
        # phone's country code against the DECLARED RESIDENTIAL ADDRESS
        # instead of nationality, and only when the address actually names a
        # country. A street/city address usually does not, in which case
        # there is nothing to compare and the check is silent rather than
        # guessed - it is a weak, low-weight signal on the rare occasions it
        # does fire, never a determination about where someone is really
        # from.
        phone = (attempt.get("phone") or "").strip()
        residence_country = self._address_country(attempt.get("address"))
        expected_prefix = (config.NATIONALITY_PHONE_PREFIX.get(residence_country)
                          if residence_country else None)
        if phone and expected_prefix and not phone.startswith(expected_prefix):
            flags += 1
            reasons.append(Reason(
                "PHONE_RESIDENCE_MISMATCH",
                "Phone country differs from declared residence (%s)" % residence_country,
                config.POINTS["PHONE_RESIDENCE_MISMATCH"],
            ))

        email = (attempt.get("email") or "").lower()
        if "@" in email:
            domain = email.rsplit("@", 1)[1]
            if domain in config.DISPOSABLE_EMAIL_DOMAINS:
                flags += 1
                reasons.append(Reason(
                    "DISPOSABLE_EMAIL",
                    "Email uses a disposable domain (%s)" % domain,
                    config.POINTS["DISPOSABLE_EMAIL"],
                ))

        document_name = attempt.get("document_name")
        form_name = attempt.get("full_name")
        if document_name and form_name:
            similarity = difflib.SequenceMatcher(
                None, document_name.lower(), form_name.lower()
            ).ratio()
            if similarity < config.NAME_SIMILARITY_THRESHOLD:
                flags += 1
                reasons.append(Reason(
                    "NAME_MISMATCH_DOCUMENT",
                    "Name on document does not match the submitted name"
                    " (similarity %.0f%%)" % (similarity * 100),
                    config.POINTS["NAME_MISMATCH_DOCUMENT"],
                ))

        features["attribute_flags"] = flags

    def _check_cross_records(self, attempt, reasons, features):
        if self.graph is None:
            return
        identity = attempt.get("claimed_user_ref")
        if not identity:
            return

        cluster = self.graph.cluster(identity)
        others = cluster - {identity}
        features["cluster_identity_count"] = len(cluster)

        # How many DIFFERENT kinds of attribute bind this cluster together.
        #
        # This is the rule that separates a family from a fraud ring, and it is
        # the single most important judgement the engine makes. A household
        # shares one thing - a device, or an address. A synthetic identity ring
        # shares several at once, because one operator is fabricating all of
        # them from one desk: same laptop, same address, same phone block, same
        # document template.
        #
        # Scoring on cluster SIZE alone punished the eight percent of genuine
        # citizens who share a service-centre kiosk exactly as hard as it
        # punished a ring, and blocked one honest applicant in twenty-four.
        # Scoring on binding STRENGTH leaves them alone while catching the ring.
        # Cluster-wide, not per-identity: a ring built from pairwise overlaps
        # (A-B share a phone, B-C share a device, C-D share an address) is
        # one connected cluster bound by three independent identifier types,
        # even though no single member directly shares more than one. Using
        # only this identity's own direct shares would miss exactly that
        # pattern - see IdentityGraph.cluster_binding_kinds.
        binding_kinds = sorted(self.graph.cluster_binding_kinds(identity))
        strong_kinds = sorted(set(binding_kinds) & graph_engine.STRONG_ATTRIBUTES)
        features["cluster_binding_kinds"] = len(binding_kinds)

        # A link is strong if it rests on something that should be unique to one
        # person (an identity document, a mobile number), or on two or more
        # independent identifiers at once. One shared laptop is not a ring.
        strong_link = bool(strong_kinds) or len(binding_kinds) >= 2

        if len(cluster) >= config.CLUSTER_SMALL_IDENTITIES and binding_kinds:
            if strong_kinds and len(binding_kinds) >= 2:
                points = config.POINTS["CROSS_RECORD_CLUSTER_LARGE"]
                rule = "CROSS_RECORD_CLUSTER_LARGE"
                verdict = "identifiers that should be unique to one person"
            elif strong_kinds or len(binding_kinds) >= 2:
                points = config.POINTS["CROSS_RECORD_CLUSTER_MEDIUM"]
                rule = "CROSS_RECORD_CLUSTER_MEDIUM"
                verdict = ("an identifier that should be unique to one person"
                           if strong_kinds else "two independent identifiers")
            else:
                points = config.POINTS["CROSS_RECORD_CLUSTER_SMALL"]
                rule = "CROSS_RECORD_CLUSTER_SMALL"
                verdict = ("a single shared device or address, which "
                           "households and public kiosks do legitimately")
            reasons.append(Reason(
                rule,
                "%d identities linked by %s: %s"
                % (len(cluster), verdict,
                   ", ".join(kind.replace("_", " ") for kind in binding_kinds)),
                points,
            ))

        if self.graph.cluster_has_blocked(identity):
            features["cluster_has_blocked"] = 1

            # Guilt by association has to be earned. If the only thing tying
            # this applicant to a blocked identity is a shared device, the most
            # likely explanation is a public terminal - a service-centre kiosk,
            # a library computer, a shared family laptop. Treating that as proof
            # means one fraudster at a government counter locks out every
            # citizen who uses that machine afterwards, which is a worse failure
            # than the fraud it prevents.
            #
            # So a weak link raises suspicion and a strong link (two or more
            # independent shared identifiers) triggers the hard control.
            if strong_link:
                reasons.append(Reason(
                    "LINKED_TO_BLOCKED_STRONG",
                    "Shares %s with an identity that was previously blocked"
                    % " and ".join(k.replace("_", " ") for k in binding_kinds),
                    config.POINTS["LINKED_TO_BLOCKED_STRONG"],
                ))
            else:
                reasons.append(Reason(
                    "LINKED_TO_BLOCKED_WEAK",
                    "Shares a %s with a previously blocked identity - weak on"
                    " its own, as devices and addresses are shared legitimately"
                    % (binding_kinds[0].replace("_", " ") if binding_kinds
                       else "connection"),
                    config.POINTS["LINKED_TO_BLOCKED_WEAK"],
                ))

    def _check_document(self, attempt, reasons, features):
        forensics_result = attempt.get("forensics")
        if not forensics_result:
            return

        ela_score = forensics_result.get("ela_score")
        if ela_score is not None:
            features["ela_score"] = round(float(ela_score), 3)
            if ela_score >= config.ELA_ANOMALY_THRESHOLD:
                reasons.append(Reason(
                    "DOCUMENT_ELA_ANOMALY",
                    "Compression analysis shows a region inconsistent with the"
                    " rest of the document (score %.1f, threshold %.1f)"
                    % (ela_score, config.ELA_ANOMALY_THRESHOLD),
                    config.POINTS["DOCUMENT_ELA_ANOMALY"],
                ))

        metadata = forensics_result.get("metadata_flags") or []
        if metadata:
            features["metadata_flag"] = 1
            editor = [flag for flag in metadata if "editing software" in flag]
            if editor:
                reasons.append(Reason(
                    "DOCUMENT_METADATA_EDITOR",
                    editor[0],
                    config.POINTS["DOCUMENT_METADATA_EDITOR"],
                ))
            else:
                reasons.append(Reason(
                    "DOCUMENT_METADATA_MISSING",
                    metadata[0],
                    config.POINTS["DOCUMENT_METADATA_MISSING"],
                ))

        doc_hash = attempt.get("document_hash")
        if doc_hash:
            identity_count = db.document_identity_count(self.conn, doc_hash)
            features["document_reuse_count"] = identity_count
            if identity_count >= 1 and attempt.get("claimed_user_ref"):
                previous = self.conn.execute(
                    "SELECT DISTINCT claimed_user_ref FROM attempts"
                    " WHERE document_hash = ? AND claimed_user_ref != ?",
                    (doc_hash, attempt["claimed_user_ref"]),
                ).fetchall()
                if previous:
                    reasons.append(Reason(
                        "DOCUMENT_REUSE",
                        "This exact document was already presented by %d other"
                        " identity/identities (%s)"
                        % (len(previous),
                           ", ".join(row["claimed_user_ref"] for row in previous[:3])),
                        config.POINTS["DOCUMENT_REUSE"],
                    ))

    def _check_verification_outcomes(self, attempt, reasons, features):
        if attempt.get("liveness_status") == "FAIL":
            features["liveness_failed"] = 1
            reasons.append(Reason(
                "LIVENESS_FAILED",
                "Liveness check did not pass",
                config.POINTS["LIVENESS_FAILED"],
            ))
        if attempt.get("login_status") == "FAIL":
            features["credential_failed"] = 1
            reasons.append(Reason(
                "CREDENTIAL_FAILED",
                "Credential check failed",
                config.POINTS["CREDENTIAL_FAILED"],
            ))

    # ------------------------------------------------------------------
    # ML layer
    # ------------------------------------------------------------------

    def _score_with_model(self, features):
        """Return (probability_of_fraud, Reason) or (None, None) on any failure."""
        try:
            probability, contributors = self.model.predict(features)
        except Exception:                   # noqa: BLE001 - never break the pipeline
            return None, None

        if probability is None:
            return None, None

        top = ", ".join(
            "%s" % name.replace("_", " ") for name, _ in contributors[:3]
        )
        reason = Reason(
            "MODEL_RISK",
            "Model estimates %.0f%% probability of fraud (driven by: %s)"
            % (probability * 100, top or "n/a"),
            0,                              # contributes through the blend, not points
            layer="MODEL",
        )
        return probability, reason

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _combine(rule_points, ml_probability, reasons):
        if ml_probability is None:
            score = float(rule_points)
        else:
            score = (config.RULE_WEIGHT * rule_points
                     + config.ML_WEIGHT * ml_probability * 100.0)

        fired = {reason.rule for reason in reasons}
        for rule, floor in config.POLICY_FLOORS.items():
            if rule in fired:
                score = max(score, floor)

        return int(max(0, min(100, round(score))))

    @staticmethod
    def _address_country(address):
        """
        Best-effort country hint from the free-text residential address
        field, by looking for one of the known country names as a whole
        word.

        Returns None when no country is named, which is the common case - a
        street/city address rarely spells one out - and the phone/residence
        check above simply does not fire on a miss. This is deliberately not
        geocoding: a name that is not found is silence, not a guess.
        """
        if not address:
            return None
        for country in config.NATIONALITY_PHONE_PREFIX:
            if re.search(r"\b%s\b" % re.escape(country), address, re.IGNORECASE):
                return country
        return None

    @staticmethod
    def _age_from_dob(date_of_birth, timestamp=None):
        if not date_of_birth:
            return None
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d"):
            try:
                born = datetime.strptime(str(date_of_birth), fmt)
                today = (datetime.strptime(timestamp[:10], "%Y-%m-%d")
                         if timestamp else datetime.now(timezone.utc))
                return today.year - born.year - (
                    (today.month, today.day) < (born.month, born.day)
                )
            except ValueError:
                continue
        return None


def apply_post_decision_reputation(conn, graph, attempt):
    """
    Feed a BLOCK back into the reputation stores.

    This is what makes the system adaptive rather than static: an IP or device
    that produced a block is cheap to recognise the next time it appears, so the
    second attack from the same infrastructure is caught faster than the first.
    """
    if attempt.get("decision") != config.DECISION_BLOCK:
        return
    if attempt.get("ip_address"):
        db.flag_ip(conn, attempt["ip_address"], "produced a blocked attempt")
    if attempt.get("device_id"):
        db.flag_device(conn, attempt["device_id"], "produced a blocked attempt")
    if graph is not None:
        graph.mark_blocked(attempt.get("claimed_user_ref"))

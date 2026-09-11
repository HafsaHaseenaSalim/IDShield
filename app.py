"""
IDShield — Flask application.

Two audiences, one engine:

  * the citizen-facing verification flow (/verify), which is what a person
    applying for a digital identity would see;
  * the analyst console (/dashboard), which is what the fraud team sees, and
    which is behind a login because a page listing everyone's risk scores is
    not something to leave open.

Run:
    python seed.py        # build the database, documents and model
    python app.py         # then open http://127.0.0.1:5000
"""

import json
import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_file, session, url_for)

import config
import database as db
import graph_engine
import ml_engine
import security
import simulator as sim
from fraud_engine import FraudEngine, apply_post_decision_reputation

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,     # not readable from JavaScript
    SESSION_COOKIE_SAMESITE="Lax",    # not sent on cross-site requests
    MAX_CONTENT_LENGTH=config.MAX_UPLOAD_BYTES,
)

limiter = security.init_rate_limiter(app)
security.init_security_headers(app)
csrf = security.init_csrf(app)


def rate_limit(rule, **kwargs):
    """
    Apply a per-IP rate limit to a view, degrading to a no-op if Flask-Limiter
    is not installed.

    This exists because the obvious-looking alternative is silently broken.
    Calling `limiter.limit(...)(view)` AFTER @app.route has run does nothing:
    Flask has already stored a reference to the undecorated function in
    app.view_functions, so the wrapper is created and thrown away. The limit
    appears in the code, reports as active, and never fires. It has to be a
    decorator applied beneath @app.route, before registration happens.
    """
    if limiter is None:
        return lambda view: view
    return limiter.limit(rule, **kwargs)

# Shared state, built once at startup rather than per request.
MODEL = ml_engine.RiskModel.load()
GRAPH = None
DOC_CACHE = {}
RUNTIME_VERSION = None


@app.before_request
def refresh_runtime():
    """Observe CLI demo resets and newly written models without a restart."""
    global GRAPH, MODEL, RUNTIME_VERSION
    conn = db.get_db()
    try:
        state = dict(conn.execute("SELECT key, value FROM runtime_state").fetchall())
    finally:
        conn.close()
    if state.get("seed_status") == "building":
        return jsonify({"error": "Demo reset in progress. Please retry when seeding finishes."}), 503
    if state.get("seed_status") == "failed":
        return jsonify({"error": "Demo reset did not finish. Run seed.py again to rebuild it."}), 503
    version = (state.get("generation"),
               os.stat(config.MODEL_PATH).st_mtime_ns if os.path.exists(config.MODEL_PATH) else None,
               os.stat(config.ELA_CALIBRATION_PATH).st_mtime_ns if os.path.exists(config.ELA_CALIBRATION_PATH) else None)
    if version != RUNTIME_VERSION:
        if RUNTIME_VERSION is not None and version[0] != RUNTIME_VERSION[0] and limiter:
            limiter.reset()
        GRAPH = None
        DOC_CACHE.clear()
        MODEL = ml_engine.RiskModel.load()
        config.ELA_ANOMALY_THRESHOLD = config._load_calibrated_ela_threshold(10.8)
        RUNTIME_VERSION = version


def get_graph():
    """Rebuild the identity graph from the database on first use."""
    global GRAPH
    if GRAPH is None:
        conn = db.get_db()
        try:
            GRAPH = graph_engine.build_from_db(conn)
        finally:
            conn.close()
    return GRAPH


def engine_for(conn):
    return FraudEngine(conn, graph=get_graph(), model=MODEL, doc_cache=DOC_CACHE)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html", model_trained=MODEL.is_trained)


@app.route("/verify")
def verify():
    return render_template("verify.html")


@app.route("/simulator")
@security.login_required
def simulator_page():
    return render_template("simulator.html")


@app.route("/dashboard")
@security.login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/customer/login", methods=["GET", "POST"])
@rate_limit(config.RATE_LIMIT_LOGIN, methods=["POST"])
def customer_login():
    """
    Citizen sign-in.

    Authentication and fraud scoring are separate controls: the password check
    below decides whether the credentials are valid, full stop, and no risk
    score changes that answer. The fraud decision only ever decides what
    happens to a password that was ALREADY correct - allow it through, make it
    clear step-up first, or refuse it despite being correct.
    """
    error = None
    pending_step_up = False
    pending_attempt_ref = None
    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        password = request.form.get("password") or ""
        if not identifier or not password or len(identifier) > 254 or len(password) > 256:
            error = "Invalid credentials."
        else:
            conn = db.get_db()
            try:
                user, password_ok = security.authenticate_customer(conn, identifier, password)

                graph = get_graph()
                attempt = {
                    "claimed_user_ref": user["user_ref"] if user else identifier[:64],
                    "full_name": user["full_name"] if user else None,
                    "date_of_birth": user["date_of_birth"] if user else None,
                    "nationality": user["nationality"] if user else None,
                    "address": user["address"] if user else None,
                    "phone": user["phone"] if user else None,
                    "email": user["email"] if user else None,
                    "ip_address": request.remote_addr or "127.0.0.1",
                    "device_id": (request.form.get("device_id") or "WEB-DEVICE").strip()[:100],
                    "timestamp": db.utcnow(),
                    "stage": config.STAGE_LOGIN,
                    "document_status": "NOT_SUBMITTED",
                    "liveness_status": "NOT_SUBMITTED",
                    "login_status": "PASS" if password_ok else "FAIL",
                    "scenario": "UNKNOWN",
                    "attempt_ref": db.next_attempt_ref(conn),
                    "user_id": user["id"] if user else None,
                }
                graph.add_attempt(attempt)
                result = engine_for(conn).evaluate(attempt)
                attempt_id = db.insert_attempt(conn, result)
                apply_post_decision_reputation(conn, graph, result)

                # Never reveal, through the message or otherwise, whether the
                # identifier matched an account.
                if not password_ok:
                    db.log_event(conn, "CUSTOMER_LOGIN_FAILURE", attempt_id,
                                 "identifier=%s" % security.mask_pii(identifier))
                    error = "Invalid credentials."
                elif result["decision"] == config.DECISION_BLOCK:
                    db.log_event(conn, "CUSTOMER_LOGIN_BLOCKED", attempt_id,
                                 "user_ref=%s" % user["user_ref"])
                    error = "Invalid credentials."
                elif result["decision"] == config.DECISION_STEP_UP:
                    db.log_event(conn, "CUSTOMER_STEP_UP_REQUIRED", attempt_id,
                                 "user_ref=%s" % user["user_ref"])
                    session.clear()
                    owner = secrets.token_hex(32)
                    session["verification_owner"] = owner
                    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
                    conn.execute(
                        "INSERT INTO step_up_challenges (attempt_id, owner, expires_at)"
                        " VALUES (?, ?, ?)",
                        (attempt_id, owner, expires.strftime("%Y-%m-%d %H:%M:%S")))
                    conn.commit()
                    pending_step_up = True
                    pending_attempt_ref = result["attempt_ref"]
                else:  # ALLOW
                    db.log_event(conn, "CUSTOMER_LOGIN_SUCCESS", attempt_id,
                                 "user_ref=%s" % user["user_ref"])
                    session.clear()
                    session["user_id"] = user["id"]
                    session["role"] = "customer"
                    session["user_ref"] = user["user_ref"]
                    return redirect(url_for("verify"))
            finally:
                conn.close()
    return render_template("customer_login.html", error=error,
                           pending_step_up=pending_step_up,
                           pending_attempt_ref=pending_attempt_ref)


@app.route("/login", methods=["GET", "POST"])
@app.route("/employee/login", methods=["GET", "POST"])
@rate_limit(config.RATE_LIMIT_LOGIN, methods=["POST"])
def analyst_login():
    error = None
    if request.method == "POST":
        identifier = (request.form.get("identifier") or request.form.get("username") or "").strip()
        conn = db.get_db()
        try:
            employee = security.authenticate_employee(conn, identifier, request.form.get("password"))
            if employee:
                session.clear()
                session["user_id"] = employee["id"]
                session["role"] = "employee"
                session["employee_ref"] = employee["employee_ref"]
                session["analyst_authenticated"] = True   # kept for the existing login_required check
                db.log_event(conn, "EMPLOYEE_LOGIN_SUCCESS", None,
                             "employee_ref=%s" % employee["employee_ref"])
                return redirect(url_for("dashboard"))
            db.log_event(conn, "EMPLOYEE_LOGIN_FAILURE", None,
                         "identifier=%s" % security.mask_pii(identifier))
        finally:
            conn.close()
        error = "Invalid credentials."
    template = "employee_login.html" if request.path == "/employee/login" else "login.html"
    return render_template(template, error=error, demo_user=config.ANALYST_USERNAME)


@app.route("/logout", methods=["GET"])
@app.route("/employee/logout", methods=["POST"])
@app.route("/customer/logout", methods=["POST"])
def logout():
    role = session.get("role")
    if role in ("employee", "customer"):
        conn = db.get_db()
        try:
            if role == "employee":
                db.log_event(conn, "EMPLOYEE_LOGOUT", None,
                             "employee_ref=%s" % session.get("employee_ref"))
            else:
                db.log_event(conn, "CUSTOMER_LOGOUT", None,
                             "user_ref=%s" % session.get("user_ref"))
        finally:
            conn.close()
    session.clear()
    return redirect(url_for("home"))


@app.route("/customer/activate", methods=["GET", "POST"])
@rate_limit(config.RATE_LIMIT_LOGIN, methods=["POST"])
def customer_activate():
    """
    Turn a just-completed, ALLOWED verification attempt into a citizen
    account - the only path a brand-new citizen has to a login, since
    /customer/login requires an account to already exist.

    Every check below is deliberately redundant with the one before it: the
    token's owner must match this session, it must not be consumed, it must
    not be expired, AND the underlying attempt's decision must still read
    ALLOW. A BLOCK - initial or via a failed step-up - never reaches this
    route with anything to redeem, because _grant_pending_activation is only
    ever called on the ALLOW path.
    """
    conn = db.get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        attempt_ref = session.get("pending_activation_attempt_ref")
        attempt = db.get_attempt(conn, attempt_ref) if attempt_ref else None
        token = (conn.execute("SELECT * FROM activation_tokens WHERE attempt_id=?",
                              (attempt["id"],)).fetchone() if attempt else None)
        valid = (
            attempt is not None and token is not None
            and secrets.compare_digest(token["owner"], session.get("verification_owner") or "")
            and not token["consumed"]
            and token["expires_at"] > db.utcnow()
            and attempt["decision"] == config.DECISION_ALLOW
        )
        if not valid:
            conn.rollback()
            session.pop("pending_activation_attempt_ref", None)
            return render_template("activate.html", expired=True, error=None)

        if request.method == "GET":
            conn.rollback()
            return render_template("activate.html", expired=False, error=None)

        identifier = (request.form.get("identifier") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        error = None
        if not identifier or not password or not confirm:
            error = "All fields are required."
        elif password != confirm:
            error = "Passwords do not match."
        elif not (8 <= len(password) <= 256) or len(identifier) > 254:
            error = "Choose a password between 8 and 256 characters."
        elif db.get_user_by_email(conn, identifier) or db.get_user_by_ref(conn, identifier):
            # Deliberately specific here (unlike login): this is a signup
            # form, and "already registered" is normal, expected feedback,
            # not an account-enumeration risk the way a login error would be.
            error = "That email or Digital ID is already registered."

        if error:
            conn.rollback()
            return render_template("activate.html", expired=False, error=error)

        # The verification form's identity reference is self-declared and not
        # guaranteed unique (it may already belong to another account, or to
        # nobody). upsert_user() only updates full_name on a user_ref
        # conflict - it would silently keep the OLD password hash - so a
        # collision here gets a fresh reference instead of reusing one.
        user_ref = attempt["claimed_user_ref"]
        if not user_ref or db.get_user_by_ref(conn, user_ref):
            user_ref = "CID-%s" % secrets.token_hex(6).upper()
        user_id = db.upsert_user(conn, {
            "user_ref": user_ref,
            "full_name": attempt["full_name"],
            "date_of_birth": attempt["date_of_birth"],
            "nationality": attempt["nationality"],
            "address": attempt["address"],
            "phone": attempt["phone"],
            "email": identifier,
            "password_hash": security.hash_password(password),
        })
        conn.execute("UPDATE activation_tokens SET consumed=1 WHERE attempt_id=?", (attempt["id"],))
        db.log_event(conn, "CUSTOMER_ACCOUNT_ACTIVATED", attempt["id"],
                     "user_ref=%s" % user_ref, commit=False)
        conn.commit()
    finally:
        conn.close()

    session.clear()
    session["user_id"] = user_id
    session["role"] = "customer"
    session["user_ref"] = user_ref
    return redirect(url_for("verify"))


# ---------------------------------------------------------------------------
# Verification API
# ---------------------------------------------------------------------------

def _grant_pending_activation(conn, attempt_id, attempt_ref):
    """
    Record that THIS session's attempt just reached ALLOW, so /customer/activate
    can turn it into a citizen account.

    Reuses the exact owner/expiry/one-time-use shape step-up challenges
    already use, and the same lazy-init pattern for `verification_owner`:
    the token is only ever redeemable by the browser session that produced
    the verified attempt in the first place.
    """
    owner = session.get("verification_owner") or secrets.token_hex(32)
    session["verification_owner"] = owner
    session["pending_activation_attempt_ref"] = attempt_ref
    expires = datetime.now(timezone.utc) + timedelta(minutes=15)
    conn.execute(
        "INSERT INTO activation_tokens (attempt_id, owner, expires_at) VALUES (?, ?, ?)",
        (attempt_id, owner, expires.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()


@app.route("/api/verify", methods=["POST"])
@rate_limit(config.RATE_LIMIT_VERIFY)
def api_verify():
    """
    The citizen-facing verification endpoint.

    Accepts the validated identity form, a required document upload and the simulated
    liveness result, scores the attempt and returns the decision with its full
    reason chain.
    """
    form = request.form
    upload = request.files.get("document")
    errors = security.validate_verification(form, upload)
    if errors:
        return jsonify({"error": "Please correct the submitted fields.", "fields": errors}), 400
    claimed_ref = (form.get("user_ref") or "").strip() or ("WEB-%s" % secrets.token_hex(3)).upper()

    conn = db.get_db()
    try:
        document_path, forensic = None, None
        upload = request.files.get("document")
        if upload and getattr(upload, "filename", ""):
            try:
                # Order is load-bearing. The upload is quarantined unmodified,
                # analysed while its EXIF and compression history are intact,
                # and only then sanitised for storage. Sanitising first would
                # mean the forensic layer analyses our own re-encode and reports
                # "no EXIF" for every document, genuine ones included.
                document_path = security.validate_and_store_upload(
                    upload, sanitise=False)
                import forensics
                forensic = forensics.analyse_document(document_path, cache=DOC_CACHE)
                if not document_path.lower().endswith(".pdf"):
                    security.sanitise_image(document_path)
                # PDFs are parsed for metadata only and never served back as active content.
                if forensic:
                    db.record_document(conn, forensic)
            except security.UploadRejected as exc:
                return jsonify({"error": str(exc)}), 400

        attempt = {
            "claimed_user_ref": claimed_ref,
            "full_name": (form.get("full_name") or "").strip(),
            "date_of_birth": (form.get("date_of_birth") or "").strip(),
            "nationality": (form.get("nationality") or "").strip(),
            "address": (form.get("address") or "").strip(),
            "phone": (form.get("phone") or "").strip(),
            "email": (form.get("email") or "").strip(),
            "ip_address": request.remote_addr or "127.0.0.1",
            "device_id": (form.get("device_id") or "WEB-DEVICE").strip(),
            "timestamp": db.utcnow(),
            "stage": config.STAGE_ONBOARDING,
            "document_path": document_path,
            "document_hash": forensic["doc_hash"] if forensic else None,
            "document_status": "PASS" if forensic else "NOT_SUBMITTED",
            "liveness_status": "PASS" if form.get("liveness") == "pass" else "FAIL",
            "login_status": "PASS" if form.get("password") else "NOT_SUBMITTED",
            "forensics": forensic,
            "scenario": "UNKNOWN",          # live traffic has no ground truth
            "attempt_ref": db.next_attempt_ref(conn),
        }

        graph = get_graph()
        graph.add_attempt(attempt)
        result = engine_for(conn).evaluate(attempt)
        attempt_id = db.insert_attempt(conn, result)

        db.log_event(conn, "WEB_VERIFICATION", attempt_id,
                     "identity=%s phone=%s" % (
                         claimed_ref, security.mask_pii(attempt["phone"])))
        apply_post_decision_reputation(conn, graph, result)
        activation_available = False
        if result["decision"] == config.DECISION_STEP_UP:
            owner = session.get("verification_owner") or secrets.token_hex(32)
            session["verification_owner"] = owner
            expires = datetime.now(timezone.utc) + timedelta(minutes=5)
            conn.execute("INSERT INTO step_up_challenges (attempt_id, owner, expires_at) VALUES (?, ?, ?)",
                         (attempt_id, owner, expires.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        elif result["decision"] == config.DECISION_ALLOW:
            # Onboarding only: a LOGIN-stage attempt never reaches this route.
            _grant_pending_activation(conn, attempt_id, result["attempt_ref"])
            activation_available = True

        return jsonify({
            "attempt_ref": result["attempt_ref"],
            "risk_score": result["risk_score"],
            "decision": result["decision"],
            "rule_points": result["rule_points"],
            "ml_probability": result["ml_probability"],
            "reasons": result["reasons"],
            "ela_image": bool(forensic and forensic.get("ela_path")),
            "activation_available": activation_available,
        })
    finally:
        conn.close()


@app.route("/api/step-up", methods=["POST"])
@rate_limit(config.RATE_LIMIT_LOGIN)
def api_step_up():
    """
    Resolve a step-up challenge.

    The demo OTP is fixed and published on screen; the point of the endpoint is
    to show that the middle decision band actually resolves to an outcome rather
    than being a dead end.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    attempt_ref = payload.get("attempt_ref")
    code = payload.get("code")
    if not isinstance(attempt_ref, str) or not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        return jsonify({"error": "An attempt reference and a six-digit code are required."}), 400

    conn = db.get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        attempt = db.get_attempt(conn, attempt_ref)
        challenge = conn.execute("SELECT * FROM step_up_challenges WHERE attempt_id=?",
                                 (attempt["id"] if attempt else None,)).fetchone()
        if not challenge or not secrets.compare_digest(challenge["owner"], session.get("verification_owner", "")):
            return jsonify({"error": "Challenge not found for this session."}), 404
        if challenge["consumed"] or attempt["decision"] != config.DECISION_STEP_UP:
            return jsonify({"error": "This challenge has already been resolved."}), 409
        if challenge["expires_at"] <= db.utcnow():
            return jsonify({"error": "This challenge has expired. Submit a new verification."}), 410

        passed = secrets.compare_digest(code, "123456")
        outcome = config.DECISION_ALLOW if passed else config.DECISION_BLOCK
        conn.execute(
            "UPDATE attempts SET step_up_result = ?, decision = ? WHERE id = ?",
            ("PASS" if passed else "FAIL", outcome, attempt["id"]),
        )
        conn.execute("UPDATE step_up_challenges SET consumed=1 WHERE attempt_id=?", (attempt["id"],))
        db.log_event(conn, "STEP_UP_%s" % ("PASSED" if passed else "FAILED"),
                     attempt["id"], commit=False)

        # A step-up on a CUSTOMER LOGIN attempt (as opposed to onboarding) is
        # the one place a customer session gets created. Only a PASS on the
        # correct owner's own attempt reaches here; a failed or expired
        # challenge never touches the session.
        activation_available = False
        if attempt["stage"] == config.STAGE_LOGIN and attempt["user_id"]:
            if passed:
                session.clear()
                session["user_id"] = attempt["user_id"]
                session["role"] = "customer"
                session["user_ref"] = attempt["claimed_user_ref"]
                db.log_event(conn, "CUSTOMER_LOGIN_SUCCESS", attempt["id"],
                             "user_ref=%s (via step-up)" % attempt["claimed_user_ref"], commit=False)
            else:
                db.log_event(conn, "CUSTOMER_LOGIN_BLOCKED", attempt["id"],
                             "user_ref=%s (step-up failed)" % attempt["claimed_user_ref"], commit=False)
        elif passed:
            # Onboarding step-up resolved to ALLOW: eligible for activation,
            # same as a direct ALLOW from /api/verify. A failed onboarding
            # step-up (BLOCK) grants nothing - no session, no token.
            _grant_pending_activation(conn, attempt["id"], attempt["attempt_ref"])
            activation_available = True

        conn.commit()
        resolved = dict(attempt)
        resolved["decision"] = outcome
        apply_post_decision_reputation(conn, get_graph(), resolved)
        return jsonify({"passed": passed, "decision": outcome,
                        "activation_available": activation_available})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Simulator API
# ---------------------------------------------------------------------------

@app.route("/api/simulate/<scenario>", methods=["POST"])
@security.login_required
def api_simulate(scenario):
    """Fire one scenario on demand — this is the live demo button."""
    if scenario not in ("legitimate", "stuffing", "synthetic", "forged"):
        return jsonify({"error": "Unknown scenario."}), 400
    conn = db.get_db()
    try:
        graph = get_graph()
        engine = engine_for(conn)
        pool = sim.ensure_document_pool(verbose=False)
        count = conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        generator = sim.TrafficSimulator(conn, engine=engine, graph=graph,
                                         doc_pool=pool, seed=config.RANDOM_SEED + count)
        base = sim.next_identity_index(conn)

        if scenario == "legitimate":
            results = [generator.legitimate_user(base)]
        elif scenario == "stuffing":
            results = generator.credential_stuffing(base)
        elif scenario == "synthetic":
            results = generator.synthetic_identity_ring(base)
        elif scenario == "forged":
            results = [generator.forged_document(base)]
        else:
            return jsonify({"error": "Unknown scenario '%s'." % scenario}), 400

        if not results:
            return jsonify({"error": "Nothing generated. Run seed.py first."}), 400

        return jsonify({
            "scenario": scenario,
            "generated": len(results),
            "attempts": [
                {
                    "attempt_ref": item["attempt_ref"],
                    "risk_score": item["risk_score"],
                    "decision": item["decision"],
                    "identity": item.get("claimed_user_ref"),
                    "reasons": item.get("reasons", []),
                }
                for item in results
            ],
            "stats": db.get_stats(conn),
        })
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Analyst API
# ---------------------------------------------------------------------------

@app.route("/api/stats")
@security.login_required
def api_stats():
    conn = db.get_db()
    try:
        stats = db.get_stats(conn)
        by_scenario = conn.execute(
            "SELECT scenario, decision, COUNT(*) AS c FROM attempts"
            " GROUP BY scenario, decision"
        ).fetchall()
        stats["breakdown"] = [dict(row) for row in by_scenario]
        # The histogram respects the same decision/scenario filters as
        # /api/attempts, so it visibly changes when the analyst changes the
        # filter controls above it instead of always showing every attempt.
        # The four summary cards above it stay unfiltered on purpose (see
        # the "Summary totals cover all attempts" caption already shown
        # next to the attempts table).
        stats["score_histogram"] = db.get_score_histogram(
            conn,
            decision=request.args.get("decision") or None,
            scenario=request.args.get("scenario") or None,
        )
        return jsonify(stats)
    finally:
        conn.close()


@app.route("/api/attempts")
@security.login_required
def api_attempts():
    try:
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError
    except ValueError:
        return jsonify({"error": "Limit must be 1–500 and offset must be non-negative."}), 400
    conn = db.get_db()
    try:
        rows = db.get_attempts(
            conn,
            limit=limit,
            offset=offset,
            decision=request.args.get("decision") or None,
            scenario=request.args.get("scenario") or None,
        )
        return jsonify([
            {
                "attempt_ref": row["attempt_ref"],
                "timestamp": row["timestamp"],
                "identity": row["claimed_user_ref"],
                "ip_address": row["ip_address"],
                "device_id": row["device_id"],
                "risk_score": row["risk_score"],
                "decision": row["decision"],
                "initial_decision": row["initial_decision"],
                "step_up_result": row["step_up_result"],
                "scenario": row["scenario"],
                "stage": row["stage"],
            }
            for row in rows
        ])
    finally:
        conn.close()


@app.route("/api/attempt/<attempt_ref>")
@security.login_required
def api_attempt(attempt_ref):
    conn = db.get_db()
    try:
        row = db.get_attempt(conn, attempt_ref)
        if row is None:
            abort(404)
        reasons = db.get_reasons(conn, row["id"])
        audit = db.get_audit_log(conn, row["id"])
        document = None
        if row["document_hash"]:
            document = conn.execute(
                "SELECT * FROM documents WHERE doc_hash = ?",
                (row["document_hash"],),
            ).fetchone()
        presentations = conn.execute("SELECT COUNT(*) FROM attempts WHERE document_hash=?",
                                     (row["document_hash"],)).fetchone()[0] if document else 0

        return jsonify({
            "attempt": {
                "attempt_ref": row["attempt_ref"],
                "timestamp": row["timestamp"],
                "identity": row["claimed_user_ref"],
                "full_name": row["full_name"],
                "ip_address": row["ip_address"],
                "device_id": row["device_id"],
                # Contact details are masked in the analyst view. An analyst
                # needs to know two records share a phone number, not what the
                # number is.
                "phone": security.mask_pii(row["phone"]),
                "email": security.mask_pii(row["email"], keep=4),
                "address": row["address"],
                "risk_score": row["risk_score"],
                "rule_points": row["rule_points"],
                "ml_probability": row["ml_probability"],
                "decision": row["decision"],
                "initial_decision": row["initial_decision"],
                "step_up_result": row["step_up_result"],
                "scenario": row["scenario"],
                "document_status": row["document_status"],
                "liveness_status": row["liveness_status"],
                "login_status": row["login_status"],
            },
            "reasons": [dict(r) for r in reasons],
            "audit": [dict(a) for a in audit],
            "document": {
                "ela_score": document["ela_score"],
                "metadata_flags": json.loads(document["metadata_flags"] or "[]"),
                "seen_count": presentations,
                "has_ela_image": bool(document["ela_path"]
                                      and os.path.exists(document["ela_path"])),
                "doc_hash": document["doc_hash"],
            } if document else None,
        })
    finally:
        conn.close()


@app.route("/api/graph/<identity>")
@security.login_required
def api_graph(identity):
    return jsonify(get_graph().to_vis_payload(identity))


@app.route("/api/metrics")
@security.login_required
def api_metrics():
    metrics = ml_engine.load_metrics() or {}
    calibration = None
    if os.path.exists(config.ELA_CALIBRATION_PATH):
        with open(config.ELA_CALIBRATION_PATH) as handle:
            calibration = json.load(handle)
    return jsonify({"model": metrics, "ela_calibration": calibration})


@app.route("/api/security")
@security.login_required
def api_security():
    return jsonify(security.security_posture())


@app.route("/api/document/<doc_hash>/ela")
@security.login_required
def api_document_ela(doc_hash):
    """Serve the ELA heatmap for one document."""
    conn = db.get_db()
    try:
        row = conn.execute(
            "SELECT ela_path FROM documents WHERE doc_hash = ?", (doc_hash,)
        ).fetchone()
        if not row or not row["ela_path"] or not os.path.exists(row["ela_path"]):
            abort(404)
        # Path comes from our own database, never from the request, so there is
        # no traversal to defend against here - but it is still resolved and
        # checked against the expected roots before being served.
        resolved = os.path.realpath(row["ela_path"])
        allowed = (os.path.realpath(config.UPLOAD_DIR),
                   os.path.realpath(config.ASSET_DOC_DIR))
        if not resolved.startswith(allowed):
            abort(403)
        return send_file(resolved, mimetype="image/png")
    finally:
        conn.close()


@app.route("/api/export.csv")
@security.login_required
def api_export():
    """Export attempts as CSV, for evidence packs and offline review."""
    import csv
    import io

    conn = db.get_db()
    try:
        rows = db.get_attempts(conn, limit=5000)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["attempt_ref", "timestamp", "identity", "ip_address",
                         "device_id", "risk_score", "decision", "scenario"])
        for row in rows:
            writer.writerow([row["attempt_ref"], row["timestamp"],
                             row["claimed_user_ref"], row["ip_address"],
                             row["device_id"], row["risk_score"],
                             row["decision"], row["scenario"]])
        from flask import Response
        return Response(
            buffer.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=idshield_attempts.csv"},
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": getattr(error, "description", "Invalid request.")}), 400

@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found."}), 404
    return render_template("error.html", code=404,
                           message="That page does not exist."), 404


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Upload exceeds the %d MB limit."
                    % (config.MAX_UPLOAD_BYTES // (1024 * 1024))}), 413


@app.errorhandler(429)
def rate_limited(_):
    return jsonify({"error": "Rate limit exceeded. This is the boundary "
                             "control working as intended."}), 429


@app.errorhandler(500)
def server_error(_):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal error."}), 500
    return render_template("error.html", code=500,
                           message="Something went wrong."), 500


def main():
    db.init_db()
    if config.SECRET_KEY_IS_DEFAULT:
        print("WARNING: using the built-in development secret key.")
        print("         Set IDSHIELD_SECRET_KEY before deploying anywhere real.")
    if not MODEL.is_trained:
        print("NOTE: no trained model found - running on the rule layer only.")
        print("      Run `python seed.py` to generate traffic and train one.")

    print("IDShield running on http://127.0.0.1:5000")
    # debug=False: the Werkzeug debugger is a remote code execution console.
    app.run(host="127.0.0.1", port=5000, debug=False)


db.init_db()
db.seed_demo_accounts()

if __name__ == "__main__":
    main()

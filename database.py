"""
IDShield — database layer.

Design notes worth defending in the demo:

  * Every SQL statement is parameterised. There is no string-interpolated SQL
    anywhere in this project (grep for f-strings near execute() to verify).
  * `attempts.timestamp` is stored as an ISO-8601 UTC string so SQLite's
    datetime() comparisons work, and so replaying traffic is deterministic.
  * The `reasons` table is the audit trail. A risk score with no stored reason
    chain is not auditable, and an identity decision you cannot explain is not
    a decision a government body can act on.
"""

import json
import os
import sqlite3
import secrets
from datetime import datetime, timezone

import config

THRESHOLD_STEP_UP_LOCAL = config.THRESHOLD_STEP_UP
THRESHOLD_BLOCK_LOCAL = config.THRESHOLD_BLOCK


# ---------------------------------------------------------------------------
# Connection handling
# ---------------------------------------------------------------------------

def get_db(path=None):
    """Open a SQLite connection with sane defaults."""
    db_path = path or config.DATABASE_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL keeps the dashboard readable while the simulator is writing.
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def utcnow():
    """Single source of truth for timestamps, in a format SQLite can compare."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        user_ref        TEXT UNIQUE NOT NULL,
        full_name       TEXT NOT NULL,
        date_of_birth   TEXT,
        nationality     TEXT,
        address         TEXT,
        phone           TEXT,
        email           TEXT,
        password_hash   TEXT,
        created_at      TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS attempts (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        attempt_ref       TEXT UNIQUE NOT NULL,
        user_id           INTEGER,
        claimed_user_ref  TEXT,
        timestamp         TEXT NOT NULL,
        stage             TEXT NOT NULL DEFAULT 'ONBOARDING',

        ip_address        TEXT,
        device_id         TEXT,
        phone             TEXT,
        address           TEXT,
        email             TEXT,
        full_name         TEXT,
        date_of_birth     TEXT,
        nationality       TEXT,

        document_path     TEXT,
        document_hash     TEXT,
        document_status   TEXT DEFAULT 'NOT_SUBMITTED',
        liveness_status   TEXT DEFAULT 'NOT_SUBMITTED',
        login_status      TEXT DEFAULT 'NOT_SUBMITTED',

        rule_points       INTEGER DEFAULT 0,
        ml_probability    REAL,
        risk_score        INTEGER DEFAULT 0,
        decision          TEXT DEFAULT 'PENDING',
        step_up_result    TEXT,

        scenario          TEXT DEFAULT 'UNKNOWN',
        features          TEXT,

        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS reasons (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        attempt_id   INTEGER NOT NULL,
        rule         TEXT NOT NULL,
        description  TEXT NOT NULL,
        points       INTEGER NOT NULL,
        layer        TEXT NOT NULL DEFAULT 'RULE',
        FOREIGN KEY (attempt_id) REFERENCES attempts(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        event       TEXT NOT NULL,
        attempt_id  INTEGER,
        details     TEXT,
        FOREIGN KEY (attempt_id) REFERENCES attempts(id) ON DELETE SET NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS flagged_ips (
        ip_address  TEXT PRIMARY KEY,
        reason      TEXT,
        first_seen  TEXT,
        hit_count   INTEGER DEFAULT 1
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS flagged_devices (
        device_id   TEXT PRIMARY KEY,
        reason      TEXT,
        first_seen  TEXT,
        hit_count   INTEGER DEFAULT 1
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS documents (
        doc_hash        TEXT PRIMARY KEY,
        path            TEXT,
        phash           TEXT,
        ela_score       REAL,
        ela_path        TEXT,
        metadata_flags  TEXT,
        first_seen_user TEXT,
        seen_count      INTEGER DEFAULT 0,
        first_seen      TEXT
    )
    """,
    """CREATE TABLE IF NOT EXISTS step_up_challenges (
        attempt_id INTEGER PRIMARY KEY REFERENCES attempts(id) ON DELETE CASCADE,
        owner TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0
    )""",
    # Short-lived, one-time, session-owned proof that a specific attempt
    # finished at ALLOW, so /customer/activate can create a citizen account
    # for it. Same shape as step_up_challenges on purpose (owner + expiry +
    # consumed), but kept as its own table: a step-up challenge is resolved
    # by an OTP code, this is resolved by setting a password, and the two
    # state machines should not be entangled.
    """CREATE TABLE IF NOT EXISTS activation_tokens (
        attempt_id INTEGER PRIMARY KEY REFERENCES attempts(id) ON DELETE CASCADE,
        owner TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS runtime_state (
        key TEXT PRIMARY KEY, value TEXT NOT NULL
    )""",
    # Employee/analyst accounts. Kept separate from `users` (citizens) rather
    # than a role flag on one table: the two audiences must never be able to
    # authenticate into each other's session just because a row happens to
    # carry the right flag.
    """CREATE TABLE IF NOT EXISTS employees (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_ref   TEXT UNIQUE NOT NULL,
        email          TEXT UNIQUE NOT NULL,
        password_hash  TEXT NOT NULL,
        role           TEXT NOT NULL DEFAULT 'analyst',
        is_active      INTEGER NOT NULL DEFAULT 1,
        created_at     TEXT NOT NULL
    )""",
    # Indexes matter here: the velocity rules run a windowed COUNT on every
    # single attempt, so an unindexed scan would dominate the replay time.
    "CREATE INDEX IF NOT EXISTS idx_attempts_ip_ts ON attempts(ip_address, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_attempts_device ON attempts(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_attempts_claimed ON attempts(claimed_user_ref, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_reasons_attempt ON reasons(attempt_id)",
]


def init_db(conn=None):
    """Create the schema. Safe to call repeatedly (all statements are IF NOT EXISTS)."""
    own = conn is None
    conn = conn or get_db()
    cur = conn.cursor()
    for statement in SCHEMA:
        cur.execute(statement)
    columns = {row[1] for row in cur.execute("PRAGMA table_info(attempts)")}
    for name in ("initial_decision", "document_name"):
        if name not in columns:
            cur.execute("ALTER TABLE attempts ADD COLUMN %s TEXT" % name)
    cur.execute("UPDATE attempts SET initial_decision = decision WHERE initial_decision IS NULL")

    user_columns = {row[1] for row in cur.execute("PRAGMA table_info(users)")}
    if "is_active" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")

    cur.execute("INSERT OR IGNORE INTO runtime_state VALUES ('generation', ?)",
                (secrets.token_hex(16),))
    conn.commit()
    if own:
        conn.close()
    return True


def reset_db(path=None, mark_building=False):
    """Reset rows in place, including WAL-safe reset on Windows."""
    conn = get_db(path)
    try:
        init_db(conn)
        for table in ("step_up_challenges", "reasons", "audit_log", "attempts",
                      "users", "documents", "flagged_ips", "flagged_devices"):
            conn.execute("DELETE FROM " + table)
        conn.execute("DELETE FROM sqlite_sequence")
        conn.execute("UPDATE runtime_state SET value=? WHERE key='generation'",
                     (secrets.token_hex(16),))
        conn.execute("INSERT OR REPLACE INTO runtime_state VALUES ('seed_status', ?)",
                     ("building" if mark_building else "ready",))
        conn.commit()
    finally:
        conn.close()
    return True


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

def upsert_user(conn, user):
    """Insert an identity if new, and return its row id either way."""
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO users (user_ref, full_name, date_of_birth, nationality,
                           address, phone, email, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_ref) DO UPDATE SET full_name = excluded.full_name
        """,
        (
            user["user_ref"], user.get("full_name"), user.get("date_of_birth"),
            user.get("nationality"), user.get("address"), user.get("phone"),
            user.get("email"), user.get("password_hash"), utcnow(),
        ),
    )
    row = cur.execute(
        "SELECT id FROM users WHERE user_ref = ?", (user["user_ref"],)
    ).fetchone()
    return row["id"] if row else None


def get_user_by_ref(conn, user_ref):
    return conn.execute(
        "SELECT * FROM users WHERE user_ref = ?", (user_ref,)
    ).fetchone()


def get_user_by_email(conn, email):
    if not email:
        return None
    return conn.execute(
        "SELECT * FROM users WHERE lower(email) = lower(?)", (email,)
    ).fetchone()


def get_employee_by_identifier(conn, identifier):
    """Look an employee up by email or employee reference, whichever was typed."""
    if not identifier:
        return None
    return conn.execute(
        "SELECT * FROM employees WHERE lower(email) = lower(?) OR employee_ref = ?",
        (identifier, identifier),
    ).fetchone()


def seed_default_customer(conn):
    """Idempotently seed the demo citizen account used by the customer portal."""
    if get_user_by_email(conn, config.CUSTOMER_DEMO_EMAIL):
        return
    import security
    upsert_user(conn, {
        "user_ref": "DEMO-CITIZEN",
        "full_name": "Demo Citizen",
        "date_of_birth": "1994-05-11",
        "nationality": "UAE",
        "address": "12 Demo Street, Dubai",
        "phone": "+971500000000",
        "email": config.CUSTOMER_DEMO_EMAIL,
        "password_hash": security.hash_password(config.CUSTOMER_DEMO_PASSWORD),
    })
    conn.commit()


def seed_default_employee(conn):
    """Idempotently seed the demo analyst account used by the employee portal."""
    if get_employee_by_identifier(conn, config.ANALYST_USERNAME):
        return
    import security
    conn.execute(
        """
        INSERT INTO employees (employee_ref, email, password_hash, role, is_active, created_at)
        VALUES (?, ?, ?, 'analyst', 1, ?)
        """,
        ("EMP-0001", config.ANALYST_USERNAME,
         security.hash_password(config.ANALYST_PASSWORD), utcnow()),
    )
    conn.commit()


def seed_demo_accounts(conn=None):
    """
    Seed the two demo logins (citizen portal, analyst portal) if they are not
    already present. Idempotent, so it is safe to call on every startup and
    every test fixture.

    Deliberately NOT called from init_db() itself: init_db() is also used by
    lightweight unit tests that assert exact row counts in `users`, and those
    should not have to account for a demo account they never asked for.
    """
    own = conn is None
    conn = conn or get_db()
    try:
        seed_default_customer(conn)
        seed_default_employee(conn)
    finally:
        if own:
            conn.close()


def next_attempt_ref(conn):
    row = conn.execute("SELECT COALESCE(MAX(id), 0) AS c FROM attempts").fetchone()
    return "ATT-%05d" % (row["c"] + 1001)


def insert_attempt(conn, attempt):
    """Insert an evaluated attempt and its reason chain in one transaction."""
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO attempts (
            attempt_ref, user_id, claimed_user_ref, timestamp, stage,
            ip_address, device_id, phone, address, email, full_name,
            date_of_birth, nationality,
            document_path, document_hash, document_status, liveness_status,
            login_status, rule_points, ml_probability, risk_score, decision,
            scenario, features
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            attempt["attempt_ref"], attempt.get("user_id"),
            attempt.get("claimed_user_ref"), attempt["timestamp"],
            attempt.get("stage", config.STAGE_ONBOARDING),
            attempt.get("ip_address"), attempt.get("device_id"),
            attempt.get("phone"), attempt.get("address"), attempt.get("email"),
            attempt.get("full_name"), attempt.get("date_of_birth"),
            attempt.get("nationality"),
            attempt.get("document_path"), attempt.get("document_hash"),
            attempt.get("document_status", "NOT_SUBMITTED"),
            attempt.get("liveness_status", "NOT_SUBMITTED"),
            attempt.get("login_status", "NOT_SUBMITTED"),
            attempt.get("rule_points", 0), attempt.get("ml_probability"),
            attempt.get("risk_score", 0), attempt.get("decision", "PENDING"),
            attempt.get("scenario", "UNKNOWN"),
            json.dumps(attempt.get("features", {})),
        ),
    )
    attempt_id = cur.lastrowid
    cur.execute("UPDATE attempts SET initial_decision=?, document_name=? WHERE id=?",
                (attempt.get("initial_decision", attempt.get("decision")),
                 attempt.get("document_name"), attempt_id))

    for reason in attempt.get("reasons", []):
        cur.execute(
            "INSERT INTO reasons (attempt_id, rule, description, points, layer)"
            " VALUES (?, ?, ?, ?, ?)",
            (attempt_id, reason["rule"], reason["description"],
             reason["points"], reason.get("layer", "RULE")),
        )

    conn.commit()
    return attempt_id


def log_event(conn, event, attempt_id=None, details=None, commit=True):
    conn.execute(
        "INSERT INTO audit_log (timestamp, event, attempt_id, details)"
        " VALUES (?, ?, ?, ?)",
        (utcnow(), event, attempt_id, details),
    )
    if commit:
        conn.commit()


def flag_ip(conn, ip_address, reason):
    conn.execute(
        """
        INSERT INTO flagged_ips (ip_address, reason, first_seen, hit_count)
        VALUES (?, ?, ?, 1)
        ON CONFLICT(ip_address) DO UPDATE SET hit_count = hit_count + 1
        """,
        (ip_address, reason, utcnow()),
    )
    conn.commit()


def flag_device(conn, device_id, reason):
    conn.execute(
        """
        INSERT INTO flagged_devices (device_id, reason, first_seen, hit_count)
        VALUES (?, ?, ?, 1)
        ON CONFLICT(device_id) DO UPDATE SET hit_count = hit_count + 1
        """,
        (device_id, reason, utcnow()),
    )
    conn.commit()


def is_ip_flagged(conn, ip_address):
    if not ip_address:
        return None
    return conn.execute(
        "SELECT * FROM flagged_ips WHERE ip_address = ?", (ip_address,)
    ).fetchone()


def is_device_flagged(conn, device_id):
    if not device_id:
        return None
    return conn.execute(
        "SELECT * FROM flagged_devices WHERE device_id = ?", (device_id,)
    ).fetchone()


def record_document(conn, doc):
    """Cache forensic results per document hash, and count reuse."""
    cur = conn.cursor()
    existing = cur.execute(
        "SELECT * FROM documents WHERE doc_hash = ?", (doc["doc_hash"],)
    ).fetchone()

    if existing:
        cur.execute(
            "UPDATE documents SET seen_count = seen_count + 1 WHERE doc_hash = ?",
            (doc["doc_hash"],),
        )
        conn.commit()
        return dict(existing), existing["seen_count"] + 1

    cur.execute(
        """
        INSERT INTO documents (doc_hash, path, phash, ela_score, ela_path,
                               metadata_flags, first_seen_user, seen_count, first_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (
            doc["doc_hash"], doc.get("path"), doc.get("phash"),
            doc.get("ela_score"), doc.get("ela_path"),
            json.dumps(doc.get("metadata_flags", [])),
            doc.get("first_seen_user"), utcnow(),
        ),
    )
    conn.commit()
    return doc, 1


def document_identity_count(conn, doc_hash):
    """How many *distinct* identities have presented this exact document."""
    if not doc_hash:
        return 0
    row = conn.execute(
        "SELECT COUNT(DISTINCT claimed_user_ref) AS c FROM attempts"
        " WHERE document_hash = ?",
        (doc_hash,),
    ).fetchone()
    return row["c"] if row else 0


# ---------------------------------------------------------------------------
# Reads used by the dashboard / API
# ---------------------------------------------------------------------------

def get_stats(conn):
    row = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN decision = 'ALLOW'   THEN 1 ELSE 0 END) AS allowed,
            SUM(CASE WHEN decision = 'STEP_UP' THEN 1 ELSE 0 END) AS stepped_up,
            SUM(CASE WHEN decision = 'BLOCK'   THEN 1 ELSE 0 END) AS blocked
        FROM attempts
        """
    ).fetchone()
    return {
        "total": row["total"] or 0,
        "allowed": row["allowed"] or 0,
        "stepped_up": row["stepped_up"] or 0,
        "blocked": row["blocked"] or 0,
    }


def get_score_histogram(conn, bucket=10, decision=None, scenario=None):
    """
    Risk scores in buckets of ten, tagged with the band each bucket falls in.

    Worth showing an analyst rather than just the three totals: a healthy
    system has a tall pile near zero and a thin tail, and a policy change that
    quietly drags the middle of the distribution upward is visible here long
    before it shows up as a complaint about false positives.

    `decision`/`scenario` mirror get_attempts()'s filters, so the histogram
    can be scoped to the same subset the analyst has filtered the attempts
    table to, instead of always describing every attempt regardless of the
    filter controls next to it.
    """
    query = ("SELECT MIN(CAST(risk_score / ? AS INTEGER), ?) AS b, COUNT(*) AS c"
            " FROM attempts WHERE 1=1")
    params = [bucket, (100 // bucket) - 1]
    if decision:
        query += " AND decision = ?"
        params.append(decision)
    if scenario:
        query += " AND scenario = ?"
        params.append(scenario)
    query += " GROUP BY b ORDER BY b"
    rows = conn.execute(query, params).fetchall()
    counts = {row["b"]: row["c"] for row in rows}

    histogram = []
    for index in range(100 // bucket):
        low = index * bucket
        high = 100 if index == (100 // bucket) - 1 else low + bucket - 1
        if low >= THRESHOLD_BLOCK_LOCAL:
            band = config.DECISION_BLOCK
        elif low >= THRESHOLD_STEP_UP_LOCAL:
            band = config.DECISION_STEP_UP
        else:
            band = config.DECISION_ALLOW
        histogram.append({
            "label": "%d-%d" % (low, high),
            "count": counts.get(index, 0),
            "band": band,
        })
    return histogram


def get_attempts(conn, limit=100, offset=0, decision=None, scenario=None):
    query = "SELECT * FROM attempts WHERE 1=1"
    params = []
    if decision:
        query += " AND decision = ?"
        params.append(decision)
    if scenario:
        query += " AND scenario = ?"
        params.append(scenario)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return conn.execute(query, params).fetchall()


def get_attempt(conn, attempt_ref):
    return conn.execute(
        "SELECT * FROM attempts WHERE attempt_ref = ?", (attempt_ref,)
    ).fetchone()


def get_reasons(conn, attempt_id):
    return conn.execute(
        "SELECT * FROM reasons WHERE attempt_id = ? ORDER BY points DESC",
        (attempt_id,),
    ).fetchall()


def get_audit_log(conn, attempt_id=None, limit=200):
    if attempt_id is not None:
        return conn.execute(
            "SELECT * FROM audit_log WHERE attempt_id = ? ORDER BY id ASC",
            (attempt_id,),
        ).fetchall()
    return conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()


def get_training_rows(conn):
    """Every attempt that has a stored feature vector and a ground-truth label."""
    return conn.execute(
        "SELECT features, scenario FROM attempts"
        " WHERE features IS NOT NULL AND scenario != 'UNKNOWN'"
    ).fetchall()


if __name__ == "__main__":
    init_db()
    print("IDShield database initialised at %s" % config.DATABASE_PATH)

"""
IDShield — synthetic traffic generator.

Produces legitimate traffic plus the three attack patterns the brief names, and
pushes every attempt through the real fraud engine. Nothing here writes a
decision directly: the simulator only decides what an attacker *does*, and the
engine independently decides what it *thinks*, which is what makes the reported
accuracy meaningful.

Two design decisions worth defending:

  1. HARD CASES ARE PLANTED ON PURPOSE.
     A generator where every attack is obvious and every legitimate user is
     pristine produces a model with 100% accuracy and no information. So a
     share of legitimate traffic shares devices (families, office kiosks,
     shared computers in a service centre) and a share of attacks are
     deliberately low-and-slow. The resulting metrics are lower and honest.

  2. TIME IS SIMULATED, NOT WALL-CLOCK.
     Each attempt is given an explicit timestamp on a synthetic timeline. That
     is what lets a credential-stuffing burst really occupy 60 seconds, and it
     is why replaying the same seed reproduces the same scores exactly.
"""

import os
import random
import json
import hashlib
from datetime import datetime, timedelta, timezone

import config
import database as db
import docgen
import forensics
from fraud_engine import FraudEngine, apply_post_decision_reputation

FIRST_NAMES = [
    "Aisha", "Omar", "Sara", "Yusuf", "Layla", "Hassan", "Mariam", "Khalid",
    "Noor", "Rashid", "Fatima", "Tariq", "Zainab", "Adil", "Huda", "Karim",
    "Priya", "Rahul", "Elena", "Marcus", "Grace", "Daniel", "Sofia", "Ibrahim",
]
LAST_NAMES = [
    "Al Mansoori", "Haddad", "Khan", "Rahman", "Farouk", "Nasser", "Sultan",
    "Aziz", "Bourne", "Silva", "Okafor", "Mendes", "Iyer", "Costa", "Reyes",
]
STREETS = [
    "Falcon Street", "Marina Walk", "Palm Avenue", "Corniche Road",
    "Jasmine Lane", "Al Wasl Road", "Sheikh Zayed Street", "Pearl Boulevard",
]
CITIES = ["Dubai", "Sharjah", "Abu Dhabi", "Ajman"]
# Offices, universities and service centres put many genuine citizens behind one
# address. These are the addresses a velocity rule must not treat as an attack.
CORPORATE_IPS = ["198.51.100.%d" % n for n in (200, 201, 202, 203)]
NATIONALITIES = ["UAE", "India", "UK", "Egypt", "Philippines", "Pakistan"]
NORMAL_EMAIL_DOMAINS = ["gmail.com", "outlook.com", "protonmail.com", "yahoo.com"]


def next_identity_index(conn):
    rows = conn.execute("SELECT user_ref FROM users WHERE user_ref LIKE 'SIM-%'")
    indices = [int(row[0][4:]) for row in rows if row[0][4:].isdigit()]
    return max(indices, default=0) + 1


class TrafficSimulator:
    """Generates and replays mixed traffic through the fraud engine."""

    def __init__(self, conn, engine=None, graph=None, seed=None, doc_pool=None, namespace="SIM"):
        self.conn = conn
        self.namespace = namespace
        self.graph = graph
        self.engine = engine or FraudEngine(conn, graph=graph)
        self.rng = random.Random(seed if seed is not None else config.RANDOM_SEED)
        self.doc_pool = doc_pool or {"clean": [], "tampered": []}
        self.doc_cache = self.engine.doc_cache
        # A fixed epoch rather than now(): timestamps feed the velocity windows,
        # so anchoring the timeline to wall-clock time would make two runs of
        # the same seed produce different scores.
        self.clock = datetime(2026, 1, 5, 8, 0, 0, tzinfo=timezone.utc)
        latest = conn.execute("SELECT MAX(timestamp) FROM attempts").fetchone()[0]
        if latest:
            self.clock = max(self.clock, datetime.strptime(latest, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _advance(self, seconds):
        self.clock += timedelta(seconds=seconds)
        return self.clock.strftime("%Y-%m-%d %H:%M:%S")

    def _identity(self, index, nationality=None):
        nationality = nationality or self.rng.choice(NATIONALITIES)
        first = self.rng.choice(FIRST_NAMES)
        last = self.rng.choice(LAST_NAMES)
        prefix = config.NATIONALITY_PHONE_PREFIX.get(nationality, "+971")
        return {
            "user_ref": "%s-%05d" % (self.namespace, index),
            "full_name": "%s %s" % (first, last),
            "date_of_birth": "%d-%02d-%02d" % (
                self.rng.randint(1965, 2004),
                self.rng.randint(1, 12),
                self.rng.randint(1, 28),
            ),
            "nationality": nationality,
            "address": "%d %s, %s" % (
                self.rng.randint(1, 220),
                self.rng.choice(STREETS),
                self.rng.choice(CITIES),
            ),
            "phone": "%s%d" % (prefix, self.rng.randint(500000000, 599999999)),
            "email": "%s.%s%d@%s" % (
                first.lower(), last.split()[-1].lower(),
                self.rng.randint(1, 999),
                self.rng.choice(NORMAL_EMAIL_DOMAINS),
            ),
        }

    def _residential_ip(self):
        # 198.51.100.0/24 and 203.0.113.0/24 are reserved for documentation
        # (RFC 5737), so nothing here can collide with a real address.
        return "198.51.100.%d" % self.rng.randint(1, 254)

    def _attacker_ip(self):
        return "203.0.113.%d" % self.rng.randint(1, 254)

    def _device(self, tag=None):
        return tag or "DEV-%04X" % self.rng.randint(0x1000, 0xFFFF)

    def _document(self, kind):
        """Draw from the shared template pool (used for deliberate reuse)."""
        pool = self.doc_pool.get(kind) or self.doc_pool.get("clean") or []
        return self.rng.choice(pool) if pool else None

    def _unique_document(self, index, tampered=False):
        """
        Generate a document belonging to exactly one identity.

        Real citizens do not share an ID document, so legitimate onboarding must
        produce a unique file. An earlier version of this simulator drew every
        applicant from a shared pool, which made the document-reuse rule fire on
        the entire legitimate population and blocked 90% of honest users. The
        reuse signal is only meaningful if reuse is genuinely abnormal.

        Files are cached on disk, so a second run reuses them instead of
        regenerating - which is also what keeps replays deterministic.
        """
        directory = os.path.join(
            config.ASSET_DOC_DIR, "tampered" if tampered else "citizens"
        )
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(
            directory, "%s_%05d.jpg" % ("forged" if tampered else "citizen", index)
        )

        # Every random draw below happens whether or not the file is cached.
        # Returning early on a cache hit would consume fewer numbers from the
        # shared stream, so a warm run would diverge from a cold one and the
        # "same seed, same result" guarantee would quietly stop holding.
        identity = {
            "full_name": "%s %s" % (self.rng.choice(FIRST_NAMES),
                                    self.rng.choice(LAST_NAMES)),
            "date_of_birth": "%d-%02d-%02d" % (
                self.rng.randint(1965, 2004),
                self.rng.randint(1, 12), self.rng.randint(1, 28)),
            "nationality": self.rng.choice(NATIONALITIES),
            "id_number": "784-%04d-%07d-%d" % (
                self.rng.randint(1960, 2005),
                self.rng.randint(0, 9999999), self.rng.randint(0, 9)),
            "expiry": "2029-%02d-%02d" % (self.rng.randint(1, 12),
                                          self.rng.randint(1, 28)),
            "altered_dob": "1996-%02d-%02d" % (self.rng.randint(1, 12),
                                               self.rng.randint(1, 28)),
        }
        # A quarter of forgers re-save the finished file to smear the
        # compression evidence. Those are the ones ELA should miss.
        leave_metadata = self.rng.random() < 0.7
        polish = 3 if self.rng.random() < 0.25 else 0
        # Genuine documents arrive with varied histories: a long-circulated PDF
        # export, or a scan taken minutes ago. The fresh scans are the honest
        # users a naive forensic threshold would falsely accuse.
        generations = 1 if self.rng.random() < 0.15 else 4

        # A cache hit is valid only for the exact generation inputs. This also
        # prevents --keep or a different seed from reusing another identity's file.
        signature = hashlib.sha256(json.dumps(
            [identity, index, tampered, leave_metadata, polish, generations], sort_keys=True
        ).encode()).hexdigest()
        path = os.path.splitext(path)[0] + "_" + signature[:16] + ".jpg"
        if os.path.exists(path):
            return path

        if tampered:
            docgen.make_tampered_document(
                identity, path, seed=index,
                leave_editor_metadata=leave_metadata, polish=polish,
            )
        else:
            docgen.make_clean_document(identity, path, seed=index,
                                       generations=generations)
        return path

    def _analyse(self, path):
        """
        Run forensics on a document and persist the result.

        Persisting matters as much as computing: the documents table is what
        lets a later pass (or a restart) reconstruct the forensic verdict
        without re-running Error Level Analysis on every file, and it is where
        reuse across identities is counted.
        """
        if not path or not os.path.exists(path):
            return None
        result = forensics.analyse_document(path, cache=self.doc_cache)
        if result:
            db.record_document(self.conn, result)
        return result

    # ------------------------------------------------------------------
    # Core submission path
    # ------------------------------------------------------------------

    def submit(self, attempt):
        """Run one attempt through the engine and persist everything."""
        if not attempt.get("timestamp"):
            attempt["timestamp"] = self._advance(self.rng.randint(5, 90))
        attempt.setdefault("stage", config.STAGE_ONBOARDING)
        attempt["attempt_ref"] = db.next_attempt_ref(self.conn)

        # The attempt joins the graph BEFORE it is scored. Otherwise a
        # first-time identity has no node, its cluster reads as empty, and the
        # feature silently becomes "have we seen this reference before?" rather
        # than "what is it connected to?" - which leaks the onboarding/login
        # distinction straight into the model.
        if self.graph is not None:
            self.graph.add_attempt(attempt)

        result = self.engine.evaluate(attempt)
        attempt_id = db.insert_attempt(self.conn, result)

        db.log_event(self.conn, "RISK_EVALUATED", attempt_id,
                     "score=%d decision=%s" % (result["risk_score"], result["decision"]),
                     commit=False)
        db.log_event(self.conn, result["decision"], attempt_id,
                     "%d reason(s)" % len(result.get("reasons", [])))

        apply_post_decision_reputation(self.conn, self.graph, result)
        return result

    # ------------------------------------------------------------------
    # Scenario 0 — legitimate traffic
    # ------------------------------------------------------------------

    def legitimate_user(self, index, shared_device=None, shared_household=None):
        """
        A normal citizen onboarding.

        `shared_device` / `shared_household` create the hard cases: real
        families and public service kiosks share hardware and addresses, and a
        detector that blocks them is useless in production. These are the
        attempts the system is *supposed* to allow despite surface-level links.
        """
        identity = self._identity(index)
        if shared_household:
            identity["address"] = shared_household

        # Real populations are messy, and every line below is a genuine source
        # of false positives in a deployed system. A detector tuned on a
        # spotless legitimate population reports accuracy it will never repeat
        # in production.
        if self.rng.random() < 0.12:
            # Expatriate keeping their home-country mobile number.
            foreign = self.rng.choice(
                [n for n in NATIONALITIES if n != identity["nationality"]])
            identity["phone"] = "%s%d" % (
                config.NATIONALITY_PHONE_PREFIX.get(foreign, "+44"),
                self.rng.randint(500000000, 599999999))

        liveness = "FAIL" if self.rng.random() < 0.10 else "PASS"   # bad lighting
        ip_address = (self.rng.choice(CORPORATE_IPS)
                      if self.rng.random() < 0.08 else self._residential_ip())

        document_path = self._unique_document(index)
        forensic = self._analyse(document_path)

        attempt = {
            "claimed_user_ref": identity["user_ref"],
            "full_name": identity["full_name"],
            "date_of_birth": identity["date_of_birth"],
            "nationality": identity["nationality"],
            "address": identity["address"],
            "phone": identity["phone"],
            "email": identity["email"],
            "ip_address": ip_address,
            "device_id": self._device(shared_device),
            "document_path": document_path,
            "document_hash": forensic["doc_hash"] if forensic else None,
            "document_status": "PASS",
            "liveness_status": liveness,
            "login_status": "PASS",
            "forensics": forensic,
            "scenario": "LEGITIMATE",
        }

        user = dict(identity)
        user["password_hash"] = None
        attempt["user_id"] = db.upsert_user(self.conn, user)
        return self.submit(attempt)

    # ------------------------------------------------------------------
    # Scenario 1 — credential stuffing
    # ------------------------------------------------------------------

    def credential_stuffing(self, index, low_and_slow=False):
        """
        One operator, one device, a list of stolen credentials.

        The `low_and_slow` variant spreads the same activity over a much longer
        window. It is the case velocity rules alone miss, and it exists so the
        demo can show honestly where a single-signal detector fails and why the
        device and graph layers matter.
        """
        attacker_ip = self._attacker_ip()
        attacker_device = self._device()

        # Victims are sampled in Python from a deterministically ordered query.
        # SQLite's RANDOM() is seeded independently of Python's, so using it
        # here made every replay pick a different victim list - the single
        # biggest source of run-to-run drift in the whole pipeline.
        population = self.conn.execute(
            "SELECT user_ref FROM users ORDER BY id ASC"
        ).fetchall()
        if not population:
            return []
        victims = self.rng.sample(
            population, min(self.rng.randint(8, 14), len(population)))

        results = []
        burst_gap = (self.rng.randint(120, 400) if low_and_slow
                     else self.rng.randint(1, 4))

        for position, victim in enumerate(victims):
            for _ in range(1 if low_and_slow else self.rng.randint(1, 3)):
                succeeded = self.rng.random() < 0.06   # stuffing rarely lands
                attempt = {
                    "claimed_user_ref": victim["user_ref"],
                    "ip_address": attacker_ip,
                    "device_id": attacker_device,
                    "stage": config.STAGE_LOGIN,
                    "timestamp": self._advance(burst_gap),
                    "document_status": "NOT_SUBMITTED",
                    "liveness_status": "NOT_SUBMITTED",
                    "login_status": "PASS" if succeeded else "FAIL",
                    "scenario": "CREDENTIAL_STUFFING",
                }
                results.append(self.submit(attempt))
        return results

    # ------------------------------------------------------------------
    # Scenario 2 — synthetic identities
    # ------------------------------------------------------------------

    def synthetic_identity_ring(self, index, size=None):
        """
        A ring of fabricated identities sharing infrastructure.

        Each identity is individually plausible - that is the whole point of a
        synthetic identity. What gives the ring away is what its members have in
        common, which is why this scenario is the one the graph layer exists for.
        """
        size = size or self.rng.randint(4, 6)
        shared_device = self._device()
        shared_phone_base = self.rng.randint(500000000, 599999998)
        shared_address = "%d %s, %s" % (
            self.rng.randint(1, 220), self.rng.choice(STREETS), self.rng.choice(CITIES)
        )
        shared_document = self._document("clean")
        shared_forensic = self._analyse(shared_document)

        results = []
        for offset in range(size):
            identity = self._identity(index + offset)

            # Shared infrastructure, varied per member so no single rule catches
            # all of them - the cluster is what is visible, not any one field.
            identity["address"] = shared_address
            if offset % 2 == 0:
                identity["phone"] = "+971%d" % (shared_phone_base + offset)
            if offset % 3 == 0:
                identity["email"] = "applicant%d@%s" % (
                    self.rng.randint(100, 999),
                    self.rng.choice(sorted(config.DISPOSABLE_EMAIL_DOMAINS)),
                )
            if offset == 0:
                identity["date_of_birth"] = "2019-%02d-%02d" % (
                    self.rng.randint(1, 12), self.rng.randint(1, 28))

            attempt = {
                "claimed_user_ref": identity["user_ref"],
                "full_name": identity["full_name"],
                "date_of_birth": identity["date_of_birth"],
                "nationality": identity["nationality"],
                "address": identity["address"],
                "phone": identity["phone"],
                "email": identity["email"],
                "ip_address": self._attacker_ip(),
                "device_id": shared_device,
                "document_path": shared_document,
                "document_hash": shared_forensic["doc_hash"] if shared_forensic else None,
                "document_status": "PASS",
                "liveness_status": "PASS" if self.rng.random() < 0.8 else "FAIL",
                "login_status": "PASS",
                "forensics": shared_forensic,
                "scenario": "SYNTHETIC_IDENTITY",
            }
            user = dict(identity)
            user["password_hash"] = None
            attempt["user_id"] = db.upsert_user(self.conn, user)
            results.append(self.submit(attempt))
        return results

    # ------------------------------------------------------------------
    # Scenario 3 — forged documents
    # ------------------------------------------------------------------

    def forged_document(self, index):
        """
        An otherwise ordinary onboarding with a tampered ID document.

        Everything except the document looks normal: normal IP, fresh device,
        plausible attributes. If the forensic layer says nothing, this attempt
        is allowed - which is precisely why it is worth having.
        """
        identity = self._identity(index)
        # Most forgeries are one-off edits; a minority reuse a template that is
        # circulating, which is what makes the document-reuse rule worth having
        # as a signal separate from the compression analysis.
        if self.rng.random() < 0.3 and self.doc_pool.get("tampered"):
            document_path = self._document("tampered")
        else:
            document_path = self._unique_document(index, tampered=True)
        forensic = self._analyse(document_path)

        # The name on a forged document often does not match the application.
        document_name = None
        if self.rng.random() < 0.4:
            document_name = "%s %s" % (
                self.rng.choice(FIRST_NAMES), self.rng.choice(LAST_NAMES)
            )

        attempt = {
            "claimed_user_ref": identity["user_ref"],
            "full_name": identity["full_name"],
            "date_of_birth": identity["date_of_birth"],
            "nationality": identity["nationality"],
            "address": identity["address"],
            "phone": identity["phone"],
            "email": identity["email"],
            # No OCR is available in the live path; do not give the simulator
            # privileged document-name evidence that real submissions lack.
            "ip_address": self._residential_ip(),
            "device_id": self._device(),
            "document_path": document_path,
            "document_hash": forensic["doc_hash"] if forensic else None,
            "document_status": "PASS",
            "liveness_status": "PASS",
            "login_status": "PASS",
            "forensics": forensic,
            "scenario": "FORGED_DOCUMENT",
        }
        user = dict(identity)
        user["password_hash"] = None
        attempt["user_id"] = db.upsert_user(self.conn, user)
        return self.submit(attempt)

    # ------------------------------------------------------------------
    # Mixed replay
    # ------------------------------------------------------------------

    def generate_mixed_traffic(self, n_legitimate=520, n_stuffing_campaigns=6,
                               n_rings=8, n_forged=70, verbose=True):
        """
        Build a full mixed dataset in a realistic order.

        Legitimate users are seeded first so the stuffing campaigns have real
        accounts to target, then attacks are interleaved.
        """
        counter = next_identity_index(self.conn)
        household = None

        for index in range(n_legitimate):
            shared_device = None
            # ~8% of citizens share a device (family or service-centre kiosk)
            if self.rng.random() < 0.08:
                shared_device = "DEV-SHARED-%02d" % self.rng.randint(1, 6)
            # ~5% share a household address
            if self.rng.random() < 0.05:
                household = household or "%d %s, %s" % (
                    self.rng.randint(1, 220), self.rng.choice(STREETS),
                    self.rng.choice(CITIES))
            else:
                household = None

            self.legitimate_user(counter, shared_device=shared_device,
                                 shared_household=household)
            counter += 1

            # Interleave attacks once there is a population to attack.
            if index == 120:
                for campaign in range(n_stuffing_campaigns):
                    self.credential_stuffing(
                        counter, low_and_slow=(campaign % 3 == 0))
            if index and index % 55 == 0 and n_rings > 0:
                self.synthetic_identity_ring(counter)
                counter += 8
                n_rings -= 1
            if index and index % 7 == 0 and n_forged > 0:
                self.forged_document(counter)
                counter += 1
                n_forged -= 1

        while n_rings > 0:
            self.synthetic_identity_ring(counter)
            counter += 8
            n_rings -= 1
        while n_forged > 0:
            self.forged_document(counter)
            counter += 1
            n_forged -= 1

        stats = db.get_stats(self.conn)
        if verbose:
            print("  generated %d attempts: %d allowed / %d step-up / %d blocked"
                  % (stats["total"], stats["allowed"], stats["stepped_up"],
                     stats["blocked"]))
        return stats


def ensure_document_pool(size=48, verbose=True, seed=None):
    """Build the shared document pool once, and reuse it on later runs."""
    os.makedirs(config.ASSET_DOC_DIR, exist_ok=True)
    seed = config.RANDOM_SEED if seed is None else seed
    directory = os.path.join(config.ASSET_DOC_DIR, "pool_%d_%d" % (size, seed))
    manifest = os.path.join(directory, "manifest.json")
    if os.path.exists(manifest):
        with open(manifest) as handle:
            saved = json.load(handle)
        pool = {kind: [os.path.join(directory, name) for name in saved[kind]]
                for kind in ("clean", "tampered")}
        if all(os.path.exists(path) for paths in pool.values() for path in paths):
            return pool

    rng = random.Random(seed)
    identities = [
        {
            "full_name": "%s %s" % (rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)),
            "date_of_birth": "%d-%02d-%02d" % (
                rng.randint(1965, 2004), rng.randint(1, 12), rng.randint(1, 28)),
            "nationality": rng.choice(NATIONALITIES),
        }
        for _ in range(size)
    ]
    pool = docgen.build_document_pool(identities, out_dir=directory, tampered_ratio=0.3, seed=seed)
    with open(manifest, "w") as handle:
        json.dump({kind: [os.path.basename(path) for path in paths]
                   for kind, paths in pool.items()}, handle)
    if verbose:
        print("  document pool: %d clean, %d tampered"
              % (len(pool["clean"]), len(pool["tampered"])))
    return pool

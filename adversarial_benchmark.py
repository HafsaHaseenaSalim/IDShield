"""
IDShield — adversarial / unseen-data benchmark generator.

simulator.py's three attack patterns (one-IP credential-stuffing bursts, a
ring that always shares BOTH device and address, and forged documents that
are never re-processed after tampering) are exactly what the Random Forest
was trained on and what most existing tests exercise. Evaluating IDShield
against more of the same tells us nothing about whether it generalizes.

This module builds a deliberately DIFFERENT, harder benchmark:

  * legitimate traffic that looks superficially suspicious (shared IPs,
    common surnames, travel, device changes, password typos) — to measure
    false positives honestly, not flatter the system with pristine users;
  * credential-stuffing campaigns that are distributed, slow, device- and
    IP-rotating, or password-spraying instead of one obvious burst;
  * synthetic-identity rings with partial/pairwise attribute overlap instead
    of one ring that shares everything;
  * document fraud that has been recompressed, resized, cropped, format-
    converted or metadata-stripped after tampering — and the same
    transforms applied to GENUINE documents, to see whether "modified file"
    gets confused with "fraudulent document".

Nothing here is used to train the model, and none of it is fed into
FraudEngine directly — this only ever produces CSV rows for
evaluate_dataset.py to score, exactly the way an unseen judge's dataset
would arrive.

Usage:
    python adversarial_benchmark.py

Writes:
    adversarial_datasets/adversarial_easy.csv
    adversarial_datasets/adversarial_medium.csv
    adversarial_datasets/adversarial_hard.csv
    adversarial_datasets/adversarial_labeled.csv   (easy+medium+hard combined)
    adversarial_datasets/documents/*.jpg|*.png     (real generated images)
"""

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PIL import Image, ImageEnhance

import config
import docgen

BASE_DIR = Path(config.BASE_DIR) / "adversarial_datasets"
DOCS_DIR = BASE_DIR / "documents"

FIELDNAMES = [
    "user_ref", "timestamp", "ip_address", "device_id", "phone", "address",
    "email", "full_name", "nationality", "date_of_birth", "login_success",
    "liveness_status", "document_path", "document_hash", "document_phash",
    "document_anomaly", "document_name", "label", "campaign_id", "attack_category",
]

# Seeds deliberately distinct from config.RANDOM_SEED / simulator.py's own
# seeding, and from each other, so the three tiers are reproducible AND
# independent of one another.
SEEDS = {"easy": 480201, "medium": 480202, "hard": 480203}

FIRST_NAMES = ["Maya", "Ethan", "Noura", "Karan", "Fadi", "Lucia", "Ben", "Amira",
              "Owen", "Farah", "Ivan", "Reem", "Cole", "Dana", "Tarek", "Nadia",
              "Miles", "Salma", "Theo", "Lina", "Grace", "Hassan", "Priya", "Jonas"]
# Deliberately reused across UNRELATED legitimate people, on purpose: a
# shared surname is a coincidence, not evidence, and the benchmark should
# check the engine doesn't quietly treat it as one.
COMMON_SURNAMES = ["Smith", "Ahmed", "Chen", "Garcia", "Patel"]
OTHER_SURNAMES = ["Farouk", "Delgado", "Voss", "Ibori", "Cheng", "Novak",
                  "Abdallah", "Reyes", "Petrov", "Kowalski"]
STREETS = ["Coral Drive", "Willow Court", "Meadow Lane", "Harbor View",
          "Cedar Path", "Union Square", "Birchwood Ave", "Founders Row"]
CITIES = ["Riverbend", "Lakeside", "Northgate", "Fairview"]
NATIONALITIES = ["UAE", "India", "UK", "Egypt", "Philippines", "Pakistan"]
EMAIL_DOMAINS = ["gmail.com", "outlook.com", "proton.me", "icloud.com"]


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


class Sequence:
    """A tiny counter for user_ref / campaign_id allocation, per difficulty tier."""
    def __init__(self, difficulty):
        self.difficulty = difficulty
        self._n = 0

    def ref(self, prefix):
        self._n += 1
        return "%s-%s-%04d" % (prefix, self.difficulty.upper(), self._n)


def _row(user_ref, timestamp, ip=None, device=None, phone=None, address=None,
        email=None, full_name=None, nationality=None, dob=None, login_success=None,
        liveness=None, document_path=None, document_hash=None, document_phash=None,
        document_anomaly=None, document_name=None, label="LEGITIMATE",
        campaign_id="", attack_category=""):
    return {
        "user_ref": user_ref,
        "timestamp": _iso(timestamp) if isinstance(timestamp, datetime) else (timestamp or ""),
        "ip_address": ip or "", "device_id": device or "", "phone": phone or "",
        "address": address or "", "email": email or "", "full_name": full_name or "",
        "nationality": nationality or "", "date_of_birth": dob or "",
        "login_success": "" if login_success is None else ("true" if login_success else "false"),
        "liveness_status": liveness or "",
        "document_path": document_path or "", "document_hash": document_hash or "",
        "document_phash": document_phash or "",
        "document_anomaly": "" if document_anomaly is None else document_anomaly,
        "document_name": document_name or "",
        "label": label, "campaign_id": campaign_id, "attack_category": attack_category,
    }


def _identity(rng, surname_pool=None):
    surname_pool = surname_pool or OTHER_SURNAMES
    first = rng.choice(FIRST_NAMES)
    last = rng.choice(surname_pool)
    nationality = rng.choice(NATIONALITIES)
    prefix = config.NATIONALITY_PHONE_PREFIX.get(nationality, "+1")
    return {
        "full_name": "%s %s" % (first, last),
        "nationality": nationality,
        "dob": "%d-%02d-%02d" % (rng.randint(1965, 2004), rng.randint(1, 12), rng.randint(1, 28)),
        "phone": "%s%d" % (prefix, rng.randint(500000000, 599999999)),
        "email": "%s.%s%d@%s" % (first.lower(), last.split()[-1].lower(),
                                 rng.randint(1, 999), rng.choice(EMAIL_DOMAINS)),
        "address": "%d %s, %s" % (rng.randint(1, 400), rng.choice(STREETS), rng.choice(CITIES)),
    }


def _residential_ip(rng):
    # 198.51.100.0/24 is reserved for documentation (RFC 5737).
    return "198.51.100.%d" % rng.randint(1, 254)


def _rotating_ip(rng):
    # A second documentation range, used for infrastructure that genuinely
    # rotates (mobile carriers, proxy pools) rather than one fixed attacker IP.
    return "203.0.113.%d" % rng.randint(1, 254)


def _device(rng):
    return "DEV-%04X" % rng.randint(0x1000, 0xFFFF)


# ---------------------------------------------------------------------------
# 1. Legitimate traffic — deliberately NOT pristine (section 3)
# ---------------------------------------------------------------------------

def gen_legitimate(rng, clock, difficulty, seq):
    rows = []

    def emit(**kwargs):
        rows.append(_row(**kwargs))

    # -- normal repeated logins from the same home device, with an
    #    occasional password mistake -----------------------------------
    for _ in range(6):
        person = _identity(rng)
        ref = seq.ref("LEG")
        device = _device(rng)
        ip = _residential_ip(rng)
        t = clock
        for visit in range(rng.randint(2, 4)):
            t += timedelta(hours=rng.randint(4, 30))
            failed_first = visit == 0 and rng.random() < 0.25
            emit(user_ref=ref, timestamp=t, ip=ip, device=device,
                phone=person["phone"], address=person["address"], email=person["email"],
                full_name=person["full_name"], nationality=person["nationality"],
                dob=person["dob"], login_success=not failed_first,
                liveness="PASS", label="LEGITIMATE")
            if failed_first:
                t += timedelta(seconds=rng.randint(20, 90))
                emit(user_ref=ref, timestamp=t, ip=ip, device=device,
                    phone=person["phone"], address=person["address"], email=person["email"],
                    full_name=person["full_name"], nationality=person["nationality"],
                    dob=person["dob"], login_success=True, liveness="PASS", label="LEGITIMATE")
        clock = t

    # -- travelling users: same device, changing IPs -------------------
    for _ in range(3):
        person = _identity(rng)
        ref = seq.ref("TRAVEL")
        device = _device(rng)
        t = clock
        for _leg in range(rng.randint(3, 5)):
            t += timedelta(hours=rng.randint(6, 48))
            emit(user_ref=ref, timestamp=t, ip=_rotating_ip(rng), device=device,
                phone=person["phone"], address=person["address"], email=person["email"],
                full_name=person["full_name"], nationality=person["nationality"],
                dob=person["dob"], login_success=True, liveness="PASS", label="LEGITIMATE")
        clock = t

    # -- users changing devices (new phone, new laptop) -----------------
    for _ in range(2):
        person = _identity(rng)
        ref = seq.ref("MULTIDEV")
        ip = _residential_ip(rng)
        t = clock
        for _dev in range(rng.randint(2, 3)):
            t += timedelta(days=rng.randint(1, 5))
            emit(user_ref=ref, timestamp=t, ip=ip, device=_device(rng),
                phone=person["phone"], address=person["address"], email=person["email"],
                full_name=person["full_name"], nationality=person["nationality"],
                dob=person["dob"], login_success=True, liveness="PASS", label="LEGITIMATE")
        clock = t

    # -- shared household IP: real family, different devices/phones ----
    household_ip = _residential_ip(rng)
    household_address = "%d %s, %s" % (rng.randint(1, 400), rng.choice(STREETS), rng.choice(CITIES))
    for _ in range(rng.randint(2, 3)):
        person = _identity(rng)
        person["address"] = household_address
        ref = seq.ref("HOUSE")
        clock += timedelta(minutes=rng.randint(1, 40))
        emit(user_ref=ref, timestamp=clock, ip=household_ip, device=_device(rng),
            phone=person["phone"], address=person["address"], email=person["email"],
            full_name=person["full_name"], nationality=person["nationality"],
            dob=person["dob"], login_success=True, liveness="PASS", label="LEGITIMATE")

    # -- corporate/NAT-style shared IP: many unrelated employees --------
    corporate_ip = _residential_ip(rng)
    for _ in range(rng.randint(5, 8)):
        person = _identity(rng)
        ref = seq.ref("CORP")
        clock += timedelta(minutes=rng.randint(2, 25))
        emit(user_ref=ref, timestamp=clock, ip=corporate_ip, device=_device(rng),
            phone=person["phone"], address=person["address"], email=person["email"],
            full_name=person["full_name"], nationality=person["nationality"],
            dob=person["dob"], login_success=True, liveness="PASS", label="LEGITIMATE")

    # -- common surnames: unrelated people, same surname, own addresses -
    for _ in range(4):
        person = _identity(rng, surname_pool=COMMON_SURNAMES)
        ref = seq.ref("NAME")
        clock += timedelta(hours=rng.randint(1, 20))
        emit(user_ref=ref, timestamp=clock, ip=_residential_ip(rng), device=_device(rng),
            phone=person["phone"], address=person["address"], email=person["email"],
            full_name=person["full_name"], nationality=person["nationality"],
            dob=person["dob"], login_success=True, liveness="PASS", label="LEGITIMATE")

    # -- reused network infrastructure: a public kiosk, many short-lived
    #    unrelated visitors across several days -------------------------
    kiosk_ip = _residential_ip(rng)
    kiosk_device = _device(rng)
    for _ in range(rng.randint(4, 7)):
        person = _identity(rng)
        ref = seq.ref("KIOSK")
        clock += timedelta(hours=rng.randint(3, 30))
        emit(user_ref=ref, timestamp=clock, ip=kiosk_ip, device=kiosk_device,
            phone=person["phone"], address=person["address"], email=person["email"],
            full_name=person["full_name"], nationality=person["nationality"],
            dob=person["dob"], login_success=True, liveness="PASS", label="LEGITIMATE")

    # -- mobile-network IP churn: one identity, several IPs in one day --
    person = _identity(rng)
    ref = seq.ref("MOBILE")
    device = _device(rng)
    t = clock
    for _ in range(rng.randint(3, 5)):
        t += timedelta(minutes=rng.randint(15, 90))
        emit(user_ref=ref, timestamp=t, ip=_rotating_ip(rng), device=device,
            phone=person["phone"], address=person["address"], email=person["email"],
            full_name=person["full_name"], nationality=person["nationality"],
            dob=person["dob"], login_success=True, liveness="PASS", label="LEGITIMATE")
    clock = t

    if difficulty in ("medium", "hard"):
        # Missing optional data: real datasets are incomplete.
        for _ in range(4):
            person = _identity(rng)
            ref = seq.ref("PARTIAL")
            clock += timedelta(hours=rng.randint(1, 12))
            emit(user_ref=ref, timestamp=clock,
                ip=_residential_ip(rng) if rng.random() < 0.7 else None,
                device=_device(rng) if rng.random() < 0.5 else None,
                phone=person["phone"] if rng.random() < 0.5 else None,
                address=person["address"] if rng.random() < 0.5 else None,
                email=person["email"], full_name=person["full_name"] if rng.random() < 0.6 else None,
                login_success=True, label="LEGITIMATE")

    if difficulty == "hard":
        # A genuinely shared address with NO other overlap at all —
        # roommates who share nothing else (device, phone, IP all distinct).
        shared_address = "%d %s, %s" % (rng.randint(1, 400), rng.choice(STREETS), rng.choice(CITIES))
        for _ in range(3):
            person = _identity(rng)
            person["address"] = shared_address
            ref = seq.ref("ROOMMATE")
            clock += timedelta(days=rng.randint(1, 3))
            emit(user_ref=ref, timestamp=clock, ip=_residential_ip(rng), device=_device(rng),
                phone=person["phone"], address=person["address"], email=person["email"],
                full_name=person["full_name"], nationality=person["nationality"],
                dob=person["dob"], login_success=True, liveness="PASS", label="LEGITIMATE")

    return rows, clock


# ---------------------------------------------------------------------------
# 2. Adversarial credential stuffing (section 4)
# ---------------------------------------------------------------------------

def _victim_pool(rng, n):
    return ["VICTIM-%s-%04d" % (rng.getrandbits(16), i) for i in range(n)]


def gen_credential_stuffing(rng, clock, difficulty, seq):
    rows = []

    def emit(**kwargs):
        rows.append(_row(**kwargs))

    # A. classic burst — many accounts, one IP, short window. Parameterized
    #    differently from simulator.py's own burst (different victim count,
    #    gap and success rate), but still recognisably a burst — this is the
    #    "easy" case.
    campaign = seq.ref("CS-BURST")
    ip = _rotating_ip(rng)
    device = _device(rng)
    victims = _victim_pool(rng, rng.randint(14, 18))
    t = clock
    for victim in victims:
        t += timedelta(seconds=rng.randint(2, 6))
        emit(user_ref=victim, timestamp=t, ip=ip, device=device,
            login_success=rng.random() < 0.08, label="CREDENTIAL_STUFFING",
            campaign_id=campaign, attack_category="CREDENTIAL_STUFFING")
    clock = t + timedelta(minutes=5)

    if difficulty in ("medium", "hard"):
        # B. distributed stuffing — one campaign, many IPs, so no single IP
        #    crosses the per-IP velocity threshold.
        campaign = seq.ref("CS-DIST")
        victims = _victim_pool(rng, rng.randint(20, 26))
        t = clock
        for victim in victims:
            t += timedelta(seconds=rng.randint(3, 12))
            emit(user_ref=victim, timestamp=t, ip=_rotating_ip(rng), device=_device(rng),
                login_success=rng.random() < 0.05, label="CREDENTIAL_STUFFING",
                campaign_id=campaign, attack_category="CREDENTIAL_STUFFING")
        clock = t + timedelta(minutes=5)

        # F. mixed successes/failures woven through an otherwise obvious
        #    burst, to see whether a few successes hide the rest.
        campaign = seq.ref("CS-MIXED")
        ip = _rotating_ip(rng)
        victims = _victim_pool(rng, rng.randint(12, 16))
        t = clock
        for i, victim in enumerate(victims):
            t += timedelta(seconds=rng.randint(2, 5))
            emit(user_ref=victim, timestamp=t, ip=ip, device=_device(rng),
                login_success=(i % 3 == 0), label="CREDENTIAL_STUFFING",
                campaign_id=campaign, attack_category="CREDENTIAL_STUFFING")
        clock = t + timedelta(minutes=5)

    if difficulty == "hard":
        # C. slow-and-low — spread across many hours, each gap well past the
        #    5-minute account-spread window and the 1-minute IP window.
        campaign = seq.ref("CS-SLOW")
        ip = _rotating_ip(rng)
        victims = _victim_pool(rng, rng.randint(10, 14))
        t = clock
        for victim in victims:
            t += timedelta(minutes=rng.randint(20, 90))
            emit(user_ref=victim, timestamp=t, ip=ip, device=_device(rng),
                login_success=rng.random() < 0.05, label="CREDENTIAL_STUFFING",
                campaign_id=campaign, attack_category="CREDENTIAL_STUFFING")
        clock = t + timedelta(hours=1)

        # D + E. rotating devices AND residential-style rotating IPs
        #    together — no two attempts share BOTH IP and device.
        campaign = seq.ref("CS-ROTATE")
        victims = _victim_pool(rng, rng.randint(16, 20))
        t = clock
        for victim in victims:
            t += timedelta(minutes=rng.randint(3, 15))
            emit(user_ref=victim, timestamp=t, ip=_rotating_ip(rng), device=_device(rng),
                login_success=rng.random() < 0.05, label="CREDENTIAL_STUFFING",
                campaign_id=campaign, attack_category="CREDENTIAL_STUFFING")
        clock = t + timedelta(hours=1)

        # G. password spraying — a handful of accounts probed many times
        #    over days, never more than one or two attempts per account in
        #    any single window, rotating infrastructure throughout.
        campaign = seq.ref("CS-SPRAY")
        victims = _victim_pool(rng, rng.randint(8, 10))
        t = clock
        for _round in range(3):
            for victim in victims:
                t += timedelta(hours=rng.randint(2, 10))
                emit(user_ref=victim, timestamp=t, ip=_rotating_ip(rng), device=_device(rng),
                    login_success=rng.random() < 0.04, label="CREDENTIAL_STUFFING",
                    campaign_id=campaign, attack_category="CREDENTIAL_STUFFING")
        clock = t + timedelta(hours=2)

    return rows, clock


# ---------------------------------------------------------------------------
# 3. Adversarial synthetic identities (section 5)
# ---------------------------------------------------------------------------

def gen_synthetic_identity(rng, clock, difficulty, seq):
    rows = []

    def emit(**kwargs):
        rows.append(_row(**kwargs))

    def member(ref, campaign, t, **overrides):
        person = _identity(rng)
        person.update(overrides)
        emit(user_ref=ref, timestamp=t, ip=overrides.get("ip") or _rotating_ip(rng),
            device=overrides.get("device") or _device(rng),
            phone=person["phone"], address=person["address"], email=person["email"],
            full_name=person["full_name"], nationality=person["nationality"],
            dob=person["dob"], login_success=True, liveness="PASS",
            label="SYNTHETIC_IDENTITY", campaign_id=campaign, attack_category="SYNTHETIC_IDENTITY")

    # A. shared phone only.
    campaign = seq.ref("SYN-PHONE")
    shared_phone = "+971%d" % rng.randint(500000000, 599999998)
    t = clock
    for i in range(4):
        t += timedelta(minutes=rng.randint(5, 60))
        member(seq.ref("SYNA"), campaign, t, phone=shared_phone)
    clock = t

    # B. shared device only.
    campaign = seq.ref("SYN-DEVICE")
    shared_device = _device(rng)
    t = clock
    for i in range(4):
        t += timedelta(minutes=rng.randint(5, 60))
        member(seq.ref("SYNB"), campaign, t, device=shared_device)
    clock = t

    if difficulty in ("medium", "hard"):
        # C. shared address, different devices/IPs.
        campaign = seq.ref("SYN-ADDR")
        shared_address = "%d %s, %s" % (rng.randint(1, 400), rng.choice(STREETS), rng.choice(CITIES))
        t = clock
        for i in range(4):
            t += timedelta(minutes=rng.randint(5, 60))
            member(seq.ref("SYNC"), campaign, t, address=shared_address)
        clock = t

        # D. pairwise chain: A-B share phone, B-C share device,
        #    C-D share address. No field is shared across all four.
        campaign = seq.ref("SYN-CHAIN")
        phone_ab = "+971%d" % rng.randint(500000000, 599999998)
        device_bc = _device(rng)
        address_cd = "%d %s, %s" % (rng.randint(1, 400), rng.choice(STREETS), rng.choice(CITIES))
        refs = [seq.ref("SYNCHAIN") for _ in range(4)]
        t = clock
        t += timedelta(minutes=rng.randint(5, 40)); member(refs[0], campaign, t, phone=phone_ab)
        t += timedelta(minutes=rng.randint(5, 40)); member(refs[1], campaign, t, phone=phone_ab, device=device_bc)
        t += timedelta(minutes=rng.randint(5, 40)); member(refs[2], campaign, t, device=device_bc, address=address_cd)
        t += timedelta(minutes=rng.randint(5, 40)); member(refs[3], campaign, t, address=address_cd)
        clock = t

    if difficulty == "hard":
        # E. sparse ring: five identities, only three of them actually
        #    connected (the other two are decoys sharing nothing).
        campaign = seq.ref("SYN-SPARSE")
        shared_device = _device(rng)
        t = clock
        for i in range(3):
            t += timedelta(hours=rng.randint(1, 12))
            member(seq.ref("SYND"), campaign, t, device=shared_device)
        for i in range(2):
            t += timedelta(hours=rng.randint(1, 12))
            member(seq.ref("SYND-DECOY"), campaign, t)
        clock = t

        # F + G. rotating infrastructure, plausible ages/attributes, one
        #    weak shared attribute (address only) spread across days.
        campaign = seq.ref("SYN-ROTATE")
        shared_address = "%d %s, %s" % (rng.randint(1, 400), rng.choice(STREETS), rng.choice(CITIES))
        t = clock
        for i in range(4):
            t += timedelta(days=rng.randint(1, 3))
            person = _identity(rng)
            person["dob"] = "%d-%02d-%02d" % (rng.randint(1975, 1999), rng.randint(1, 12), rng.randint(1, 28))
            member(seq.ref("SYNE"), campaign, t, address=shared_address,
                  dob=person["dob"], ip=_rotating_ip(rng), device=_device(rng))
        clock = t

    return rows, clock


# ---------------------------------------------------------------------------
# 4. Adversarial document fraud (section 6/7) — real generated images
# ---------------------------------------------------------------------------

def _doc_fields(rng):
    return {
        "full_name": "%s %s" % (rng.choice(FIRST_NAMES), rng.choice(OTHER_SURNAMES)),
        "date_of_birth": "%d-%02d-%02d" % (rng.randint(1965, 2004), rng.randint(1, 12), rng.randint(1, 28)),
        "nationality": rng.choice(NATIONALITIES),
        "id_number": "784-%04d-%07d-%d" % (rng.randint(1960, 2005), rng.randint(0, 9999999), rng.randint(0, 9)),
        "expiry": "2030-%02d-%02d" % (rng.randint(1, 12), rng.randint(1, 28)),
        "altered_dob": "1997-%02d-%02d" % (rng.randint(1, 12), rng.randint(1, 28)),
    }


def _resize(src, dst, scale=0.6):
    with Image.open(src) as img:
        w, h = img.size
        img.convert("RGB").resize((max(1, int(w * scale)), max(1, int(h * scale)))).save(
            dst, "JPEG", quality=90)
    return dst


def _crop(src, dst, margin=0.08):
    with Image.open(src) as img:
        w, h = img.size
        dx, dy = int(w * margin), int(h * margin)
        img.convert("RGB").crop((dx, dy, w - dx, h - dy)).save(dst, "JPEG", quality=90)
    return dst


def _convert_png(src, dst):
    with Image.open(src) as img:
        img.convert("RGB").save(dst, "PNG")     # PNG carries no JPEG history
    return dst


def _strip_and_recompress(src, dst, passes=2, quality=88):
    with Image.open(src) as img:
        current = img.convert("RGB")
    for _ in range(passes):
        current.save(dst, "JPEG", quality=quality)   # no exif kwarg: metadata is dropped
        current = Image.open(dst).convert("RGB")
    return dst


def _adjust_brightness_contrast(src, dst, brightness=1.15, contrast=0.92):
    with Image.open(src) as img:
        adjusted = ImageEnhance.Brightness(img.convert("RGB")).enhance(brightness)
        adjusted = ImageEnhance.Contrast(adjusted).enhance(contrast)
        adjusted.save(dst, "JPEG", quality=90)
    return dst


def _screenshot_like(src, dst):
    """Downsize then upsize and heavily recompress — as if the document were
    photographed off a screen rather than submitted as the original file."""
    with Image.open(src) as img:
        w, h = img.size
        small = img.convert("RGB").resize((max(1, w // 2), max(1, h // 2)))
        small.resize((w, h)).save(dst, "JPEG", quality=55)
    return dst


def gen_document_fraud(rng, clock, difficulty, seq):
    rows = []
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    seed = SEEDS[difficulty] + 777

    def emit(**kwargs):
        rows.append(_row(**kwargs))

    def rel(path):
        return "documents/" + Path(path).name

    clean_fields = _doc_fields(rng)
    forged_fields = _doc_fields(rng)
    clean_base = DOCS_DIR / ("legit_base_%s.jpg" % difficulty)
    forged_base = DOCS_DIR / ("forged_base_%s.jpg" % difficulty)
    docgen.make_clean_document(clean_fields, str(clean_base), seed=seed, generations=4)
    docgen.make_tampered_document(
        forged_fields, str(forged_base), seed=seed + 1,
        leave_editor_metadata=(difficulty == "easy"),   # only the easy case leaves the obvious tell
        polish=(3 if difficulty in ("medium", "hard") else 0),   # anti-forensic re-saves for the harder tiers
    )

    transforms = [
        ("resized", lambda s, d: _resize(s, d)),
        ("recompressed_stripped", lambda s, d: _strip_and_recompress(s, d)),
        ("brightness_contrast", lambda s, d: _adjust_brightness_contrast(s, d)),
    ]
    if difficulty in ("medium", "hard"):
        transforms.append(("cropped", lambda s, d: _crop(s, d)))
        transforms.append(("png_converted", lambda s, d: _convert_png(s, d)))
    if difficulty == "hard":
        transforms.append(("screenshot_like", lambda s, d: _screenshot_like(s, d)))
        transforms.append(("double_recompressed", lambda s, d: _strip_and_recompress(s, d, passes=4, quality=80)))

    # -- forged documents, one transform each: does detection survive the
    #    transform, or does it evade the exact-hash and metadata checks? --
    campaign = seq.ref("DOC-FRAUD")
    t = clock
    for name, fn in transforms:
        ext = ".png" if name == "png_converted" else ".jpg"
        out = DOCS_DIR / ("forged_%s_%s%s" % (difficulty, name, ext))
        fn(str(forged_base), str(out))
        t += timedelta(minutes=rng.randint(10, 90))
        identity = _identity(rng)
        emit(user_ref=seq.ref("DOCF"), timestamp=t, ip=_residential_ip(rng), device=_device(rng),
            phone=identity["phone"], address=identity["address"], email=identity["email"],
            full_name=identity["full_name"], nationality=identity["nationality"],
            dob=identity["dob"], login_success=True, liveness="PASS",
            document_path=rel(out), label="DOCUMENT_FRAUD",
            campaign_id=campaign, attack_category="DOCUMENT_FRAUD")

    # -- the SAME transforms applied to a GENUINE document: these must not
    #    be mistaken for fraud just because the file was modified. --------
    for name, fn in transforms:
        ext = ".png" if name == "png_converted" else ".jpg"
        out = DOCS_DIR / ("legit_%s_%s%s" % (difficulty, name, ext))
        fn(str(clean_base), str(out))
        t += timedelta(minutes=rng.randint(10, 90))
        identity = _identity(rng)
        emit(user_ref=seq.ref("DOCL"), timestamp=t, ip=_residential_ip(rng), device=_device(rng),
            phone=identity["phone"], address=identity["address"], email=identity["email"],
            full_name=identity["full_name"], nationality=identity["nationality"],
            dob=identity["dob"], login_success=True, liveness="PASS",
            document_path=rel(out), label="LEGITIMATE")

    return rows, t


# ---------------------------------------------------------------------------
# 5. Assembly
# ---------------------------------------------------------------------------

def build_dataset(difficulty):
    rng = random.Random(SEEDS[difficulty])
    seq = Sequence(difficulty)
    clock = datetime(2026, 3, 2, 6, 0, 0, tzinfo=timezone.utc) + timedelta(days=SEEDS[difficulty] % 5)

    rows = []
    legit, clock = gen_legitimate(rng, clock, difficulty, seq)
    rows += legit
    stuffing, clock = gen_credential_stuffing(rng, clock, difficulty, seq)
    rows += stuffing
    synthetic, clock = gen_synthetic_identity(rng, clock, difficulty, seq)
    rows += synthetic
    documents, clock = gen_document_fraud(rng, clock, difficulty, seq)
    rows += documents

    # Section 8: out-of-order source records. Real exports are not sorted by
    # event time, and evaluate_dataset.py is responsible for putting them
    # back in order before scoring — so the FILE order here is shuffled,
    # deliberately decoupled from the chronological order above.
    rng.shuffle(rows)
    return rows


def write_csv(rows, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    all_rows = []
    for difficulty in ("easy", "medium", "hard"):
        rows = build_dataset(difficulty)
        write_csv(rows, BASE_DIR / ("adversarial_%s.csv" % difficulty))
        all_rows.extend(rows)
        legit = sum(1 for r in rows if r["label"] == "LEGITIMATE")
        print("  %-6s: %d records (%d legitimate, %d attack)"
             % (difficulty, len(rows), legit, len(rows) - legit))

    write_csv(all_rows, BASE_DIR / "adversarial_labeled.csv")
    print("Wrote %s (%d records total)" % (BASE_DIR / "adversarial_labeled.csv", len(all_rows)))
    print("Documents written to %s" % DOCS_DIR)


if __name__ == "__main__":
    main()

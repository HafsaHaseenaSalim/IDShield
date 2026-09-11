"""
IDShield — synthetic identity document generator (simulation side only).

This module fabricates the ID-card images the simulator feeds through the
pipeline. It is kept strictly separate from forensics.py: the detector has no
knowledge of how these files were produced, which is what makes the forensic
results meaningful rather than circular.

How the tampering is done, and why it is detectable:

  A JPEG that has been saved repeatedly at the same quality converges towards a
  fixed point - each further save changes it less and less. So we save the
  clean card four times. For a tampered card we save it three times, then paste
  a freshly rendered region (photo swap and/or altered date of birth) and save
  once more.

  The result is a single image whose background has been through four
  compression generations while the pasted region has been through one. Error
  Level Analysis re-saves the image once more and measures how much each region
  still changes; the background barely moves, the pasted region moves a lot.

  That is a real compression artefact, not a watermark we planted for the demo
  to find. Nothing is written into the file to tell the detector where the edit
  is - it has to infer it.
"""

import os
import random

from PIL import Image, ImageDraw, ImageFont

import config

CARD_SIZE = (620, 390)
JPEG_QUALITY = 92

NATIONALITIES = ["UAE", "India", "UK", "Egypt", "Philippines", "Pakistan"]


def _font(size):
    """Pillow's built-in font, with a fallback for older versions."""
    try:
        return ImageFont.load_default(size=size)
    except TypeError:                        # Pillow < 10.1
        return ImageFont.load_default()


def _photo_block(width, height, rng):
    """
    A deterministic pseudo-portrait: smooth background gradient, head and
    shoulders, then a light blur.

    The blur is not cosmetic. Per-pixel noise is pathological for JPEG - it
    never settles at a fixed point, so a genuine photo would show as much
    residual compression error as a spliced one and Error Level Analysis would
    be meaningless. Real portraits are dominated by low frequencies, so the
    synthetic ones have to be too, or the forensic layer would be testing an
    artefact of the generator rather than the technique.
    """
    from PIL import ImageFilter

    bg = tuple(rng.randint(90, 170) for _ in range(3))
    skin = (rng.randint(180, 225), rng.randint(140, 185), rng.randint(120, 160))
    cloth = tuple(rng.randint(40, 110) for _ in range(3))

    img = Image.new("RGB", (width, height), bg)
    draw = ImageDraw.Draw(img)

    # vertical lighting gradient across the backdrop
    for y in range(height):
        shade = int(30 * (y / height)) - 15
        draw.line(
            [(0, y), (width, y)],
            fill=tuple(max(0, min(255, c + shade)) for c in bg),
        )

    cx = width // 2
    draw.ellipse([cx - 52, int(height * 0.62), cx + 52, height + 40], fill=cloth)
    draw.ellipse([cx - 38, int(height * 0.18), cx + 38, int(height * 0.68)], fill=skin)
    hair = tuple(max(0, c - 90) for c in skin)
    draw.chord([cx - 40, int(height * 0.14), cx + 40, int(height * 0.52)], 180, 360, fill=hair)

    return img.filter(ImageFilter.GaussianBlur(1.4))


def _draw_card(fields, rng):
    """Render a complete ID card as an in-memory image."""
    card = Image.new("RGB", CARD_SIZE, (238, 241, 246))
    draw = ImageDraw.Draw(card)

    draw.rectangle([0, 0, CARD_SIZE[0], 62], fill=(18, 52, 96))
    draw.text((22, 14), "UNITED SIMULATION AUTHORITY", font=_font(20), fill=(255, 255, 255))
    draw.text((22, 38), "DIGITAL IDENTITY CARD  -  SPECIMEN", font=_font(13), fill=(168, 196, 232))

    photo = _photo_block(150, 185, rng)
    card.paste(photo, (26, 85))
    draw.rectangle([26, 85, 176, 270], outline=(120, 130, 145), width=2)

    left = 200
    rows = [
        ("NAME", fields["full_name"]),
        ("DATE OF BIRTH", fields["date_of_birth"]),
        ("NATIONALITY", fields["nationality"]),
        ("ID NUMBER", fields["id_number"]),
        ("EXPIRY", fields["expiry"]),
    ]
    y = 92
    for label, value in rows:
        draw.text((left, y), label, font=_font(12), fill=(110, 120, 135))
        draw.text((left, y + 16), str(value), font=_font(17), fill=(20, 28, 40))
        y += 40

    draw.rectangle([0, 300, CARD_SIZE[0], CARD_SIZE[1]], fill=(226, 230, 237))
    mrz = "IDSIM%s<<%s<<<<<<<<<<<<<<" % (
        fields["id_number"].replace("-", ""),
        fields["full_name"].upper().replace(" ", "<"),
    )
    draw.text((22, 318), mrz[:52], font=_font(15), fill=(60, 70, 85))
    draw.text((22, 344), "%s%s" % (fields["date_of_birth"].replace("-", ""),
                                   "<" * 20), font=_font(15), fill=(60, 70, 85))
    return card


def _compress_generations(image, path, generations, exif=None):
    """Save/reload `generations` times so the file settles near its fixed point."""
    current = image
    for index in range(generations):
        save_kwargs = {"quality": JPEG_QUALITY}
        if exif is not None and index == generations - 1:
            save_kwargs["exif"] = exif
        current.save(path, "JPEG", **save_kwargs)
        current = Image.open(path).convert("RGB")
    return current


def _camera_exif():
    exif = Image.Exif()
    exif[271] = "SimuCam"                    # Make
    exif[272] = "SC-200"                     # Model
    exif[305] = "SimuCam Firmware 2.1"       # Software
    exif[306] = "2024:03:11 09:22:14"        # DateTime
    exif[36867] = "2024:03:11 09:22:14"      # DateTimeOriginal
    return exif


def _editor_exif():
    exif = Image.Exif()
    exif[271] = "SimuCam"
    exif[272] = "SC-200"
    exif[305] = "Adobe Photoshop 25.1 (Windows)"
    exif[306] = "2024:07:02 23:41:08"         # modified long after capture
    exif[36867] = "2024:03:11 09:22:14"
    return exif


def make_clean_document(fields, out_path, seed=0, generations=4):
    """
    A genuine document.

    `generations` is how many times the file has been saved before we see it.
    A document that has been emailed around for months is deep at its
    compression fixed point; one scanned five minutes ago is not, and it will
    show a higher error level despite being completely genuine. Varying this
    across the legitimate population is what stops the forensic layer from
    looking better than it is.
    """
    rng = random.Random(seed)
    card = _draw_card(fields, rng)
    _compress_generations(card, out_path, generations=generations,
                          exif=_camera_exif())
    return out_path


def make_tampered_document(fields, out_path, seed=0, leave_editor_metadata=True,
                           polish=0):
    """
    A forged document: compressed three generations, then edited, then saved
    once more. The photo is swapped and the date of birth is over-typed - the
    two edits a real document forger most often makes.
    """
    rng = random.Random(seed)
    card = _draw_card(fields, rng)
    card = _compress_generations(card, out_path, generations=3)

    # --- the edit itself -------------------------------------------------
    forger_rng = random.Random(seed + 9999)
    replacement_photo = _photo_block(150, 185, forger_rng)
    card.paste(replacement_photo, (26, 85))

    draw = ImageDraw.Draw(card)
    draw.rectangle([200, 128, 420, 152], fill=(238, 241, 246))
    altered_dob = fields.get("altered_dob", "1998-01-01")
    draw.text((200, 130), altered_dob, font=_font(17), fill=(20, 28, 40))

    # A careless forger leaves the editor's fingerprint in the metadata. A
    # careful one scrubs it and writes plausible camera metadata back. If every
    # forgery left an editor tag, the metadata check alone would solve the task
    # and the compression analysis would be decoration - so only some do, and
    # the rest have to be caught by Error Level Analysis or not at all.
    exif = _editor_exif() if leave_editor_metadata else _camera_exif()
    card.save(out_path, "JPEG", quality=JPEG_QUALITY, exif=exif)

    # `polish` is anti-forensics. Re-saving the finished forgery several more
    # times drives the pasted region towards the same fixed point as the rest of
    # the image, which is a known and cheap way to defeat Error Level Analysis.
    # Some forgers do this. Modelling them is the difference between measuring
    # how well the technique works and measuring how easy we made it.
    if polish:
        reopened = Image.open(out_path).convert("RGB")
        _compress_generations(reopened, out_path, generations=polish, exif=exif)
    return out_path


def build_document_pool(identities, out_dir=None, tampered_ratio=0.25, seed=42):
    """
    Build a reusable pool of documents.

    Generating one image per attempt would be slow and pointless; a pool of a
    few dozen, referenced by many attempts, is both faster and more realistic -
    fraud rings reuse templates, which is exactly what the reuse rule detects.

    Returns {"clean": [paths], "tampered": [paths]}.
    """
    out_dir = out_dir or config.ASSET_DOC_DIR
    os.makedirs(out_dir, exist_ok=True)
    rng = random.Random(seed)

    pool = {"clean": [], "tampered": []}
    for index, identity in enumerate(identities):
        fields = {
            "full_name": identity["full_name"],
            "date_of_birth": identity["date_of_birth"],
            "nationality": identity.get("nationality", rng.choice(NATIONALITIES)),
            "id_number": "784-%04d-%07d-%d" % (
                rng.randint(1960, 2005), rng.randint(0, 9999999), rng.randint(0, 9)),
            "expiry": "2029-%02d-%02d" % (rng.randint(1, 12), rng.randint(1, 28)),
            "altered_dob": "1996-%02d-%02d" % (rng.randint(1, 12), rng.randint(1, 28)),
        }

        is_tampered = rng.random() < tampered_ratio
        name = "doc_%03d_%s.jpg" % (index, "tampered" if is_tampered else "clean")
        path = os.path.join(out_dir, name)

        if is_tampered:
            # Only three quarters of forgeries leave editor metadata behind.
            # If every forgery carried the same tell, the metadata rule alone
            # would solve the task and the other layers would look decorative.
            make_tampered_document(
                fields, path, seed=index,
                leave_editor_metadata=rng.random() < 0.75,
            )
            pool["tampered"].append(path)
        else:
            make_clean_document(fields, path, seed=index)
            pool["clean"].append(path)

    return pool

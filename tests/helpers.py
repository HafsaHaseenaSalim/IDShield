import io
from pypdf import PdfWriter


def verification_data(**overrides):
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=200)
    stream = io.BytesIO()
    writer.write(stream)
    stream.seek(0)
    data = {"full_name": "Test Citizen", "date_of_birth": "1994-05-11",
            "nationality": "UAE", "phone": "+971509876543",
            "email": "test@example.com", "address": "12 Test Street",
            "device_id": "TEST-DEVICE", "liveness": "pass",
            "document": (stream, "identity.pdf")}
    data.update(overrides)
    return data

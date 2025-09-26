# tests/test_anton_eof.py
from pathlib import Path
import sys
import pytest

SERVER_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVER_DIR / "src"))

import watermarking_utils as WM 

KEY = "course-demo-key"

def minimal_pdf(with_eof: bool = True) -> bytes:
    parts = [
        b"%PDF-1.4\n",
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
    ]
    pdf = b"".join(parts)
    if with_eof:
        pdf += b"%%EOF\n"
    return pdf


def test_method_registered():
    assert "anton-eof" in WM.METHODS


def test_applicability_true_false():
    assert WM.is_watermarking_applicable("anton-eof", minimal_pdf(True))
    assert not WM.is_watermarking_applicable("anton-eof", b"not a pdf")


def test_roundtrip():
    pdf = minimal_pdf(True)
    secret = "identity=Jean;session=XYZ"
    out = WM.apply_watermark("anton-eof", pdf, secret, KEY)
    got = WM.read_watermark("anton-eof", out, KEY)
    assert got == secret


def test_handles_missing_eof_and_appends_it():
    pdf = minimal_pdf(False)  # no %%EOF in source
    out = WM.apply_watermark("anton-eof", pdf, "s123", KEY)
    assert out.endswith(b"%%EOF\n")
    assert WM.read_watermark("anton-eof", out, KEY) == "s123"


def test_last_tag_wins():
    pdf = minimal_pdf(True)
    a = WM.apply_watermark("anton-eof", pdf, "first", KEY)
    b = WM.apply_watermark("anton-eof", a, "second", KEY)
    assert WM.read_watermark("anton-eof", b, KEY) == "second"


def test_hmac_tamper_detected():
    pdf = minimal_pdf(True)
    out = WM.apply_watermark("anton-eof", pdf, "secret", KEY)

    tail = out[-8192:] if len(out) > 8192 else out
    prefix = b"%ANTONWM "
    i = tail.rfind(prefix)
    assert i != -1
    j = tail.find(b"\n", i)
    if j == -1:
        j = len(tail)
    line = tail[i:j]

    b64_part, sig = line[len(prefix):].split(b" ", 1)
    sig_list = bytearray(sig)
    sig_list[0] = ord(b"0" if sig_list[0] != ord(b"0") else b"1")
    tampered_line = prefix + b64_part + b" " + bytes(sig_list)

    tampered = out.replace(line, tampered_line, 1)
    with pytest.raises(ValueError):
        WM.read_watermark("anton-eof", tampered, KEY)

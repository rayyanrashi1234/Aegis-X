# tests/test_scanner.py - Aegis-X Deterministic Scanner & API Test Suite
"""
Aegis-X Automated Pytest Test Suite
====================================
Tests:
- Benign PDF vs Synthetic Malicious PDF (/JavaScript + /OpenAction)
- File type magic-byte extension mismatches and RTLO
- Typosquatting (Damerau-Levenshtein) and IP-literal links
- Scam SMS with urgency, OTP/KYC, and dangerous link
- Shannon entropy analysis
- Offline password strength checking
- Flask API endpoints & Sliding-Window Rate Limiter
"""

import os
import sys
import json
try:
    import pytest
except ImportError:
    pytest = None

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Compatibility decorator for pytest fixtures
def fixture(func):
    if pytest is not None:
        return pytest.fixture(func)
    return func

from scanner import (
    scan_pdf,
    check_file_type,
    file_hash,
    check_link,
    check_message,
    file_entropy,
    check_password,
    final_verdict,
    damerau_levenshtein_distance,
)
from server import app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@fixture
def benign_pdf_bytes() -> bytes:
    """Fixture generating a minimal, clean synthetic PDF."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n120\n%%EOF"
    )


@fixture
def malicious_pdf_bytes() -> bytes:
    """Fixture generating a synthetic malicious PDF with /JavaScript and /OpenAction."""
    return (
        b"%PDF-1.5\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<< /Type /Action /S /JavaScript /JS (app.alert('Compromised'); util.printd();) >>\n"
        b"endobj\n"
        b"xref\n0 5\n"
        b"trailer\n<< /Root 1 0 R >>\n%%EOF"
    )


@fixture
def mismatched_exe_pdf_bytes() -> bytes:
    """Fixture of a Windows PE binary disguised with .pdf filename."""
    return b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode."


@fixture
def client():
    """Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ---------------------------------------------------------------------------
# Unit Tests: Scanner Core
# ---------------------------------------------------------------------------

def test_benign_pdf(benign_pdf_bytes):
    """Assert clean PDF returns low score and SAFE verdict."""
    result = scan_pdf(benign_pdf_bytes, "clean_document.pdf")
    assert result.score < 30.0
    assert result.verdict == "SAFE"
    assert result.verdict_color == "emerald"
    assert not any("JavaScript" in r for r in result.reasons)


def test_malicious_pdf(malicious_pdf_bytes):
    """Assert synthetic malicious PDF flags /JavaScript and /OpenAction."""
    result = scan_pdf(malicious_pdf_bytes, "exploit_drop.pdf")
    assert result.score >= 70.0
    assert result.verdict == "DANGEROUS"
    assert result.verdict_color == "red"
    # Check that reasons contain required exploit tokens
    reasons_joined = " ".join(result.reasons)
    assert "JavaScript" in reasons_joined
    assert "OpenAction" in reasons_joined
    assert any(f.category == "PDF_DRIVEBY_SIGNATURE" for f in result.findings)


def test_extension_mismatch(mismatched_exe_pdf_bytes):
    """Assert Windows PE binary with .pdf extension triggers CRITICAL mismatch."""
    findings = check_file_type("statement.pdf", mismatched_exe_pdf_bytes)
    assert len(findings) > 0
    categories = [f.category for f in findings]
    assert "EXTENSION_MISMATCH_EXECUTABLE" in categories
    assert findings[0].severity == "CRITICAL"
    assert findings[0].score_impact >= 80.0


def test_double_extension():
    """Assert double extension e.g. invoice.pdf.exe triggers HIGH severity."""
    dummy_data = b"Some file contents"
    findings = check_file_type("invoice.pdf.exe", dummy_data)
    assert any(f.category == "DOUBLE_EXTENSION" for f in findings)
    double_ext_finding = next(f for f in findings if f.category == "DOUBLE_EXTENSION")
    assert double_ext_finding.severity == "HIGH"
    assert double_ext_finding.score_impact >= 50.0


def test_rtlo_filename():
    """Assert Right-to-Left Override Unicode character triggers CRITICAL finding."""
    rtlo_filename = "document\u202epdf.exe"
    findings = check_file_type(rtlo_filename, b"test")
    assert any(f.category == "RTLO_OBFUSCATION" for f in findings)
    rtlo_finding = next(f for f in findings if f.category == "RTLO_OBFUSCATION")
    assert rtlo_finding.severity == "CRITICAL"
    assert rtlo_finding.score_impact >= 90.0


def test_damerau_levenshtein_distance():
    """Verify Damerau-Levenshtein calculation including transpositions."""
    assert damerau_levenshtein_distance("paypal", "paypal") == 0
    assert damerau_levenshtein_distance("paypa", "paypal") == 1   # insertion
    assert damerau_levenshtein_distance("paypall", "paypal") == 1  # deletion
    assert damerau_levenshtein_distance("paypal", "payapl") == 1  # transposition
    assert damerau_levenshtein_distance("paypa1", "paypal") == 1  # substitution


def test_typosquat_link():
    """Assert typosquatting URL is detected and scored appropriately."""
    result = check_link("http://paypa1.com/login")
    assert result.score >= 50.0
    assert any(f.category in ("TYPOSQUATTING", "BRAND_IMPERSONATION") for f in result.findings)
    reasons_str = " ".join([f.description for f in result.findings])
    assert "paypal" in reasons_str.lower()


def test_ip_literal_link():
    """Assert raw IP-literal link triggers IP_LITERAL_HOST finding."""
    result = check_link("http://192.168.1.105/banking/login.php")
    assert any(f.category == "IP_LITERAL_HOST" for f in result.findings)
    assert result.score >= 45.0


def test_scam_sms_message():
    """Assert scam SMS with urgency, OTP/KYC, and malicious link triggers DANGEROUS."""
    scam_text = (
        "URGENT: Your bank account will be suspended within 24 hours due to missing KYC! "
        "Do not share your OTP. Verify your credentials immediately at http://paypa1.com/verify"
    )
    result = check_message(scam_text)
    assert result.score >= 70.0
    assert result.verdict == "DANGEROUS"
    categories = [f.category for f in result.findings]
    assert "URGENCY" in categories
    assert "OTP_KYC" in categories
    assert len(result.urls_found) == 1


def test_benign_message():
    """Assert standard friendly text returns SAFE."""
    text = "Hey, are we still meeting for lunch at 1 PM today? Let me know!"
    result = check_message(text)
    assert result.score < 30.0
    assert result.verdict == "SAFE"


def test_file_entropy():
    """Assert high-entropy bytes are flagged as packed/encrypted."""
    # Low entropy: repeated sequence
    low_ent = b"A" * 8192
    res_low = file_entropy(low_ent)
    assert res_low.overall_entropy < 1.0
    assert not res_low.is_packed_or_encrypted

    # High entropy: pseudorandom uniform bytes
    import random
    random.seed(42)
    high_ent = bytes([random.randint(0, 255) for _ in range(8192)])
    res_high = file_entropy(high_ent)
    assert res_high.overall_entropy >= 7.2
    assert res_high.is_packed_or_encrypted


def test_password_checker():
    """Assert common password is weak/DANGEROUS and complex password is strong/SAFE."""
    weak = check_password("password123")
    assert weak.score < 35.0
    assert weak.verdict == "DANGEROUS"
    assert any(f.category == "COMMON_PASSWORD_MATCH" for f in weak.findings)

    strong = check_password("K9#mQ$8x!vZ2@Lp")
    assert strong.score >= 70.0
    assert strong.verdict == "SAFE"
    assert strong.entropy_bits >= 60.0


# ---------------------------------------------------------------------------
# API Integration Tests
# ---------------------------------------------------------------------------

def test_api_ping(client):
    """Test /api/ping heartbeat endpoint."""
    res = client.get("/api/ping")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "online"
    assert "uptime_seconds" in data
    assert "timestamp" in data


def test_android_soc_api_routes_return_json(client):
    """The Android client health check and consent-based analysis return JSON."""
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.get_json()["status"] == "online"

    rejected = client.post("/api/v1/analyze_file", json={"filename": "sample.txt", "content": "sample"})
    assert rejected.status_code == 403
    assert rejected.get_json()["status"] == "CONSENT_REQUIRED"

    analyzed = client.post("/api/v1/analyze_file", json={
        "filename": "sample.txt",
        "content": "sample clean file",
        "consent": True,
        "authorize_escalation": True,
    })
    assert analyzed.status_code == 200
    assert analyzed.get_json()["status"] == "SUCCESS"
    assert "incident_report" in analyzed.get_json()


def test_api_check_link_endpoint(client):
    """Test /api/check_link endpoint with typosquat link."""
    res = client.post("/api/check_link", json={"url": "http://g00gle.com/login"})
    assert res.status_code == 200
    data = res.get_json()
    assert "score" in data
    assert "verdict" in data
    assert "reasons" in data
    assert data["target_type"] == "url"


def test_api_check_message_endpoint(client):
    """Test /api/check_message endpoint."""
    res = client.post("/api/check_message", json={"text": "URGENT: Verify OTP now"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["target_type"] == "message"
    assert data["score"] >= 35.0


def test_api_check_password_endpoint(client):
    """Test /api/check_password endpoint."""
    res = client.post("/api/check_password", json={"password": "123456_qwerty"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["target_type"] == "password"
    assert data["verdict"] in ("DANGEROUS", "SUSPICIOUS")


def test_api_scan_file_endpoint(client, malicious_pdf_bytes):
    """Test /api/scan_file multipart upload."""
    import io
    data = {
        "file": (io.BytesIO(malicious_pdf_bytes), "exploit_sample.pdf")
    }
    res = client.post("/api/scan_file", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["target_type"] == "file"
    assert json_data["score"] >= 70.0
    assert json_data["verdict"] == "DANGEROUS"


def test_api_report_endpoint(client):
    """Test /api/report incident reporting endpoint."""
    payload = {
        "target": "exploit_sample.pdf",
        "target_type": "file",
        "score": 95.0,
        "reasons": ["Embedded JavaScript detected", "Auto-Open action executed"]
    }
    res = client.post("/api/report", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["status"] == "REPORT_RECORDED"
    assert data["escalated_to_sos"] is True
    assert "plain_text_report" in data

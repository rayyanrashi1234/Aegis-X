# tests/run_tests.py - Aegis-X Test Suite Runner (Standard Library unittest compatible)
import sys
import os
import unittest
import io
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner import (
    scan_pdf, check_file_type, file_hash, check_link, check_message,
    file_entropy, check_password, final_verdict, damerau_levenshtein_distance
)
from server import app

class TestAegisXDeterministicScanner(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

        self.benign_pdf = (
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f \ntrailer\n<< /Size 4 /Root 1 0 R >>\n%%EOF"
        )
        self.malicious_pdf = (
            b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('Malware');) >>\nendobj\n"
            b"xref\n0 5\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
        )
        self.exe_disguised_as_pdf = (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode."
        )

    def test_01_benign_pdf(self):
        res = scan_pdf(self.benign_pdf, "invoice.pdf")
        self.assertLess(res.score, 30.0)
        self.assertEqual(res.verdict, "SAFE")
        self.assertEqual(res.verdict_color, "emerald")

    def test_02_malicious_pdf(self):
        res = scan_pdf(self.malicious_pdf, "trojan.pdf")
        self.assertGreaterEqual(res.score, 70.0)
        self.assertEqual(res.verdict, "DANGEROUS")
        self.assertEqual(res.verdict_color, "red")
        reasons_text = " ".join(res.reasons)
        self.assertIn("JavaScript", reasons_text)
        self.assertIn("OpenAction", reasons_text)

    def test_03_extension_mismatch(self):
        findings = check_file_type("statement.pdf", self.exe_disguised_as_pdf)
        self.assertTrue(len(findings) > 0)
        categories = [f.category for f in findings]
        self.assertIn("EXTENSION_MISMATCH_EXECUTABLE", categories)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_04_double_extension(self):
        findings = check_file_type("document.pdf.exe", b"dummy")
        self.assertTrue(any(f.category == "DOUBLE_EXTENSION" for f in findings))

    def test_05_rtlo_filename(self):
        findings = check_file_type("report\u202epdf.exe", b"dummy")
        self.assertTrue(any(f.category == "RTLO_OBFUSCATION" for f in findings))

    def test_06_damerau_levenshtein(self):
        self.assertEqual(damerau_levenshtein_distance("paypal", "paypal"), 0)
        self.assertEqual(damerau_levenshtein_distance("paypa", "paypal"), 1)
        self.assertEqual(damerau_levenshtein_distance("paypa1", "paypal"), 1)
        self.assertEqual(damerau_levenshtein_distance("payapl", "paypal"), 1)

    def test_07_typosquat_link(self):
        res = check_link("http://paypa1.com/login")
        self.assertGreaterEqual(res.score, 50.0)
        self.assertTrue(any(f.category in ("TYPOSQUATTING", "BRAND_IMPERSONATION") for f in res.findings))

    def test_08_ip_literal_link(self):
        res = check_link("http://192.168.1.100/admin")
        self.assertTrue(any(f.category == "IP_LITERAL_HOST" for f in res.findings))

    def test_09_scam_message(self):
        text = "URGENT: Your KYC is suspended! Share OTP immediately at http://paypa1.com/verify"
        res = check_message(text)
        self.assertGreaterEqual(res.score, 70.0)
        self.assertEqual(res.verdict, "DANGEROUS")

    def test_10_benign_message(self):
        res = check_message("Meeting at 3 PM in the conference room.")
        self.assertLess(res.score, 30.0)
        self.assertEqual(res.verdict, "SAFE")

    def test_11_file_entropy(self):
        import random
        random.seed(42)
        packed_bytes = bytes([random.randint(0, 255) for _ in range(8192)])
        res = file_entropy(packed_bytes)
        self.assertGreaterEqual(res.overall_entropy, 7.2)
        self.assertTrue(res.is_packed_or_encrypted)

    def test_12_password_check(self):
        weak = check_password("password123")
        self.assertEqual(weak.verdict, "DANGEROUS")
        strong = check_password("X7$qL#9v!mP4@kZ")
        self.assertEqual(strong.verdict, "SAFE")

    def test_13_api_ping(self):
        res = self.client.get("/api/ping")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "online")

    def test_14_api_scan_file(self):
        data = {"file": (io.BytesIO(self.malicious_pdf), "exploit.pdf")}
        res = self.client.post("/api/scan_file", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertEqual(json_data["verdict"], "DANGEROUS")
        self.assertGreaterEqual(json_data["score"], 70.0)

    def test_15_api_report(self):
        payload = {
            "target": "exploit.pdf",
            "target_type": "file",
            "score": 90.0,
            "reasons": ["Embedded JavaScript", "Auto Open"]
        }
        res = self.client.post("/api/report", json=payload)
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.get_json()["escalated_to_sos"])

    def test_16_sliding_window_rate_limiter(self):
        # Fire 25 rapid requests with custom IP
        ip_header = {"X-Forwarded-For": "203.0.113.42"}
        allowed_count = 0
        rate_limited_count = 0

        for i in range(25):
            res = self.client.post("/api/check_link", json={"url": "http://example.com"}, headers=ip_header)
            if res.status_code == 200:
                allowed_count += 1
            elif res.status_code == 429:
                rate_limited_count += 1

        self.assertEqual(allowed_count, 20)
        self.assertEqual(rate_limited_count, 5)

if __name__ == "__main__":
    unittest.main()

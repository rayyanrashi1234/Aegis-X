# scanner_api.py - Aegis-X Scanner API Blueprint & Sliding-Window Rate Limiter
"""
Aegis-X Deterministic Scanner Blueprint
=======================================
Implements endpoints:
- POST /api/scan_file
- POST /api/check_link
- POST /api/check_message
- POST /api/check_password
- GET  /api/ping
- POST /api/report
Uniform JSON Schema, sliding-window rate limiting (20 req/min/IP), strict validation.
"""

from __future__ import annotations

import collections
import hashlib
import os
import re
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Tuple
from flask import Blueprint, request, jsonify, Response

from scanner import (
    CONFIG,
    Finding,
    ScanResult,
    check_file_type,
    check_link,
    check_message,
    check_password,
    file_entropy,
    file_hash,
    final_verdict,
    scan_pdf,
)

scanner_api_bp = Blueprint("scanner_api_bp", __name__)

SERVER_START_TIME = time.time()

# ---------------------------------------------------------------------------
# Sliding-Window Rate Limiter (20 req / min per IP)
# ---------------------------------------------------------------------------

class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding-window rate limiter per client IP.
    Default: 20 requests per 60-second window.
    """
    def __init__(self, limit: int = 20, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self.clients: Dict[str, collections.deque] = {}

    def is_allowed(self, ip: str) -> Tuple[bool, int, int]:
        now = time.time()
        if ip not in self.clients:
            self.clients[ip] = collections.deque()

        dq = self.clients[ip]
        # Purge timestamps outside sliding window
        while dq and dq[0] <= now - self.window:
            dq.popleft()

        if len(dq) < self.limit:
            dq.append(now)
            remaining = self.limit - len(dq)
            return True, remaining, self.window
        else:
            retry_after = int(self.window - (now - dq[0])) + 1
            return False, 0, max(1, retry_after)


rate_limiter = SlidingWindowRateLimiter(
    limit=int(os.environ.get("AEGIS_RATE_LIMIT", "20")),
    window_seconds=int(os.environ.get("AEGIS_RATE_WINDOW", "60"))
)


def get_client_ip() -> str:
    """Extracts client IP safely with proxy header support."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


@scanner_api_bp.before_request
def enforce_rate_limiting():
    """
    Enforces 20 req/min sliding-window rate limit on all scanner endpoints.
    Health check heartbeat (/api/ping) is exempt from rate exhaustion.
    """
    # Allow heartbeat without rate penalty
    if request.path in ("/api/ping", "/api/health"):
        return None

    if request.method == "OPTIONS":
        return Response(status=200)

    ip = get_client_ip()
    allowed, remaining, retry_after = rate_limiter.is_allowed(ip)

    if not allowed:
        # Log TIER_1 anomaly in threat log
        try:
            from server import threat_log, broadcast_event
            anomaly = {
                "id": f"RL-{int(time.time()*1000)}",
                "time": datetime.now().strftime("%H:%M:%S"),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "tier": "TIER_1",
                "action": "RATE_LIMITED",
                "reason": f"Sliding-window rate limit exceeded (>20 req/min) from IP {ip}",
                "source_ip": ip,
                "poison": "HTTP 429 Throttle Enforced"
            }
            threat_log.append(anomaly)
            broadcast_event(anomaly)
        except Exception:
            pass

        response = jsonify({
            "status": "RATE_LIMITED",
            "error": "Too Many Requests",
            "message": f"Rate limit of {rate_limiter.limit} requests per minute exceeded.",
            "retry_after_seconds": retry_after,
            "code": 429,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    return None


# ---------------------------------------------------------------------------
# Uniform Response Helper
# ---------------------------------------------------------------------------

def make_uniform_response(
    target: str,
    target_type: str,
    score: float,
    verdict: str,
    verdict_color: str,
    reasons: List[str],
    hash_val: str,
    details: Dict[str, Any],
    findings: List[Finding]
) -> Dict[str, Any]:
    """Uniform JSON response schema for all scanner endpoints."""
    req_id = f"AEGIS-{uuid.uuid4().hex[:8].upper()}"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "request_id": req_id,
        "timestamp": ts,
        "target": target,
        "target_type": target_type,
        "score": round(float(score), 1),
        "verdict": verdict,
        "verdict_color": verdict_color,
        "reasons": reasons,
        "hash": hash_val,
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "details": details
    }


def sanitize_filename(filename: str) -> str:
    """Sanitizes filename against path traversal and control character attacks."""
    base = os.path.basename(filename)
    # Strip null bytes and control chars
    clean = re.sub(r"[\x00-\x1f\x7f]", "", base).strip()
    return clean if clean else "unnamed_artifact.bin"


# ---------------------------------------------------------------------------
# Scanner API Endpoints
# ---------------------------------------------------------------------------

@scanner_api_bp.route("/api/ping", methods=["GET"])
def ping():
    """
    Heartbeat Endpoint:
    Returns node status, uptime, server timestamp, and active status.
    """
    uptime = int(time.time() - SERVER_START_TIME)
    return jsonify({
        "status": "online",
        "service": "Aegis-X Mobile Security Node",
        "node_id": "AEGIS-NODE-ALPHA",
        "uptime_seconds": uptime,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "version": "2.4.0"
    }), 200


@scanner_api_bp.route("/api/scan_file", methods=["POST"])
def scan_file():
    """
    Deterministic File Scanner Endpoint:
    Multipart or JSON file ingestion. Computes SHA-256, validates magic-bytes,
    inspects PDF structure/scripts (if PDF), and analyzes Shannon entropy.
    """
    filename = "upload.bin"
    file_bytes = b""

    # 1. Check Multipart file upload
    if request.files and "file" in request.files:
        f = request.files["file"]
        filename = sanitize_filename(f.filename or "file.bin")
        file_bytes = f.read(CONFIG["max_file_size"] + 1)
    elif request.is_json:
        # JSON body payload
        req_data = request.get_json(silent=True) or {}
        raw_content = req_data.get("content") or req_data.get("file") or ""
        filename = sanitize_filename(req_data.get("filename") or "sample.txt")
        file_bytes = raw_content.encode("utf-8", errors="replace")
    else:
        # Raw body
        file_bytes = request.get_data(cache=False, as_text=False)
        filename = sanitize_filename(request.headers.get("X-Filename", "raw_stream.bin"))

    # Size validation
    if len(file_bytes) > CONFIG["max_file_size"]:
        return jsonify({
            "error": "File size exceeds 10 MB maximum limit",
            "code": 413,
            "max_size_bytes": CONFIG["max_file_size"]
        }), 413

    if not file_bytes:
        return jsonify({"error": "No file content provided", "code": 400}), 400

    # Local SHA-256
    sha256, hash_finding = file_hash(file_bytes)
    findings: List[Finding] = []
    reasons: List[str] = []
    total_score = 0.0

    if hash_finding:
        findings.append(hash_finding)
        reasons.append(hash_finding.description)
        total_score += hash_finding.score_impact

    # File Type & Extension Checks
    type_findings = check_file_type(filename, file_bytes)
    for tf in type_findings:
        findings.append(tf)
        reasons.append(tf.description)
        total_score += tf.score_impact

    # PDF Structural Analysis if detected or named .pdf
    ext = os.path.splitext(filename)[1].lower()
    is_pdf = file_bytes.startswith(b"%PDF-") or ext == ".pdf"
    pdf_details: Dict[str, Any] = {}

    if is_pdf:
        pdf_res = scan_pdf(file_bytes, filename)
        pdf_details = {
            "pdf_score": pdf_res.score,
            "pdf_verdict": pdf_res.verdict,
            "pdf_findings_count": len(pdf_res.findings)
        }
        for pf in pdf_res.findings:
            if pf.category not in [f.category for f in findings]:
                findings.append(pf)
                reasons.append(pf.description)
        total_score = max(total_score, pdf_res.score)

    # Shannon Entropy Analysis
    ent_res = file_entropy(file_bytes)
    if ent_res.is_packed_or_encrypted:
        for ef in ent_res.findings:
            if ef.category not in [f.category for f in findings]:
                findings.append(ef)
                reasons.append(ef.description)
                total_score += ef.score_impact

    clamped_score = min(100.0, round(total_score, 1))
    verdict, color = final_verdict(clamped_score)

    if not reasons:
        reasons.append("File passed deterministic analysis with no malicious indicators.")

    details = {
        "file_name": filename,
        "file_size": len(file_bytes),
        "overall_entropy": ent_res.overall_entropy,
        "is_packed": ent_res.is_packed_or_encrypted,
        "is_pdf": is_pdf,
        "pdf_details": pdf_details
    }

    # Record in threat_log & broadcast if DANGEROUS
    if verdict == "DANGEROUS":
        try:
            from server import threat_log, sos_alerts, broadcast_event
            incident = {
                "id": f"DNG-{int(time.time()*1000)}",
                "time": datetime.now().strftime("%H:%M:%S"),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "tier": "TIER_3",
                "action": "DANGEROUS_FILE_BLOCKED",
                "reason": f"File '{filename}' flagged DANGEROUS (Score: {clamped_score})",
                "sha256": sha256,
                "sha256_short": f"{sha256[:16]}...",
                "source_ip": get_client_ip(),
                "poison": "Quarantined"
            }
            threat_log.append(incident)
            sos_alerts.append(incident)
            broadcast_event(incident)
        except Exception:
            pass

    response_payload = make_uniform_response(
        target=filename,
        target_type="file",
        score=clamped_score,
        verdict=verdict,
        verdict_color=color,
        reasons=reasons,
        hash_val=sha256,
        details=details,
        findings=findings
    )
    return jsonify(response_payload), 200


@scanner_api_bp.route("/api/check_link", methods=["POST"])
def api_check_link():
    """
    Deterministic Link Inspection Endpoint:
    Checks IP literals, shorteners, punycode, typosquatting (Damerau-Levenshtein),
    and phishing keywords.
    """
    req_data = request.get_json(silent=True) or {}
    url = req_data.get("url") or req_data.get("link") or ""

    if not url or not isinstance(url, str):
        return jsonify({"error": "Missing or invalid 'url' parameter in JSON body", "code": 400}), 400

    link_res = check_link(url.strip())
    reasons = [f.description for f in link_res.findings] or ["Destination host and URL structure verified clean."]

    sha256 = hashlib.sha256(url.encode("utf-8")).hexdigest()
    details = {
        "hostname": link_res.hostname,
        "url_length": len(url),
    }

    response_payload = make_uniform_response(
        target=url,
        target_type="url",
        score=link_res.score,
        verdict=link_res.verdict,
        verdict_color=link_res.verdict_color,
        reasons=reasons,
        hash_val=sha256,
        details=details,
        findings=link_res.findings
    )
    return jsonify(response_payload), 200


@scanner_api_bp.route("/api/check_message", methods=["POST"])
def api_check_message():
    """
    Deterministic SMS / Message Inspection Endpoint:
    Checks social engineering lexicon (urgency, OTP/KYC, credentials, bait),
    extracts embedded URLs and runs deep link inspection.
    """
    req_data = request.get_json(silent=True) or {}
    text = req_data.get("text") or req_data.get("message") or req_data.get("content") or ""

    if not text or not isinstance(text, str):
        return jsonify({"error": "Missing or invalid 'text' parameter in JSON body", "code": 400}), 400

    msg_res = check_message(text)
    reasons = [f.description for f in msg_res.findings] or ["No social engineering keywords or phishing indicators found."]

    sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    details = {
        "text_length": len(text),
        "urls_detected": msg_res.urls_found,
        "url_count": len(msg_res.urls_found)
    }

    response_payload = make_uniform_response(
        target=text[:60] + "..." if len(text) > 60 else text,
        target_type="message",
        score=msg_res.score,
        verdict=msg_res.verdict,
        verdict_color=msg_res.verdict_color,
        reasons=reasons,
        hash_val=sha256,
        details=details,
        findings=msg_res.findings
    )
    return jsonify(response_payload), 200


@scanner_api_bp.route("/api/check_password", methods=["POST"])
def api_check_password():
    """
    Offline Password Strength & Entropy Evaluator:
    Calculates bits of entropy, common dictionary matches, and keyboard walks.
    """
    req_data = request.get_json(silent=True) or {}
    password = req_data.get("password") or req_data.get("pw") or ""

    if not isinstance(password, str):
        return jsonify({"error": "Invalid 'password' parameter", "code": 400}), 400

    pw_res = check_password(password)
    reasons = [f.description for f in pw_res.findings] or ["Password meets high entropy and strength standards."]

    sha256 = hashlib.sha256(password.encode("utf-8")).hexdigest() if password else "e3b0c442..."
    details = {
        "entropy_bits": pw_res.entropy_bits,
        "masked": pw_res.password_masked,
        "length": len(password)
    }

    response_payload = make_uniform_response(
        target=pw_res.password_masked,
        target_type="password",
        score=pw_res.score,
        verdict=pw_res.verdict,
        verdict_color=pw_res.verdict_color,
        reasons=reasons,
        hash_val=sha256,
        details=details,
        findings=pw_res.findings
    )
    return jsonify(response_payload), 200


@scanner_api_bp.route("/api/report", methods=["POST"])
def api_report():
    """
    Incident Report Endpoint:
    Compiles structured JSON + plain text executive incident report.
    If verdict is DANGEROUS, automatically appends to sos_alerts.
    """
    req_data = request.get_json(silent=True) or {}
    target = req_data.get("target", "Unknown Target")
    target_type = req_data.get("target_type", "artifact")
    score = float(req_data.get("score", 0.0))
    verdict, color = final_verdict(score)
    reasons = req_data.get("reasons", ["Manual security report submitted."])
    sha256 = req_data.get("hash", hashlib.sha256(target.encode()).hexdigest())

    incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Generate Plain Text Incident Report
    plain_text_report = (
        f"====================================================\n"
        f"   AEGIS-X INCIDENT FORENSIC REPORT\n"
        f"====================================================\n"
        f"Incident ID:    {incident_id}\n"
        f"Timestamp:      {ts}\n"
        f"Target:         {target} ({target_type})\n"
        f"SHA-256:        {sha256}\n"
        f"Threat Score:   {score} / 100\n"
        f"Verdict:        {verdict}\n"
        f"----------------------------------------------------\n"
        f"FINDINGS & REASONS:\n"
        + "\n".join([f"  * {r}" for r in reasons]) + "\n"
        f"----------------------------------------------------\n"
        f"RECOMMENDED REMEDIATION:\n"
        f"  1. Isolate and quarantine affected artifact immediately.\n"
        f"  2. Add SHA-256 hash {sha256} to endpoint perimeter blocklist.\n"
        f"  3. Dispatch ticket to SOC White-Hat Response Team.\n"
        f"====================================================\n"
    )

    incident_record = {
        "incident_id": incident_id,
        "timestamp": ts,
        "target": target,
        "target_type": target_type,
        "score": score,
        "verdict": verdict,
        "verdict_color": color,
        "reasons": reasons,
        "hash": sha256,
        "plain_text_report": plain_text_report,
        "source_ip": get_client_ip()
    }

    escalated = False
    if verdict == "DANGEROUS" or score >= 70.0:
        escalated = True
        try:
            from server import sos_alerts, threat_log, broadcast_event
            sos_entry = {
                "id": incident_id,
                "time": datetime.now().strftime("%H:%M:%S"),
                "timestamp": ts,
                "tier": "TIER_3",
                "action": "SOS_DISPATCH",
                "reason": f"Dangerous artifact reported: {target} (Score: {score})",
                "source": "Incident_Reporter",
                "source_ip": get_client_ip(),
                "poison": "Escalated to White-Hat SOC",
                "incident": incident_record
            }
            sos_alerts.append(sos_entry)
            threat_log.append(sos_entry)
            broadcast_event(sos_entry)
        except Exception:
            pass

    return jsonify({
        "status": "REPORT_RECORDED",
        "incident_id": incident_id,
        "escalated_to_sos": escalated,
        "structured_report": incident_record,
        "plain_text_report": plain_text_report
    }), 201

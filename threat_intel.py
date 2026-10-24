# threat_intel.py - Aegis-X Threat Intelligence, File Analysis & Incident Reporting Module
"""
Aegis-X Threat Intelligence & Incident Response Core
=====================================================
1. User-Consent File Analysis Engine (/api/v1/analyze_file)
2. Foreign Attack Detection & Geo-Profiling
3. Structured Incident Report Generation (JSON with IoCs, Severity, Remediation)
4. User Consent & White-Hat Hacker Escalation Workflow
"""

import hashlib
import json
import re
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify, Response

# Maximum file analysis size: 10 MB
MAX_FILE_SIZE = 10 * 1024 * 1024

# Mock Threat Actor Geo-Database & Threat Attribution
KNOWN_FOREIGN_APT_ORIGINS = {
    "RU": {"actor": "APT28 / Fancy Bear (Cross-Border)", "threat_category": "State-Sponsored Cyber Espionage", "risk_factor": "HIGH"},
    "CN": {"actor": "Volt Typhoon / APT41 (Cross-Border)", "threat_category": "Critical Infrastructure Infiltration", "risk_factor": "HIGH"},
    "KP": {"actor": "Lazarus Group (Foreign Infiltration)", "threat_category": "Financial Heist & Ransomware Staging", "risk_factor": "CRITICAL"},
    "IR": {"actor": "Charming Kitten / APT35", "threat_category": "Wiper & Credential Harvesting", "risk_factor": "HIGH"},
    "TOR": {"actor": "Anonymous Tor Exit Relay", "threat_category": "Anonymized Cross-Border Routing", "risk_factor": "MEDIUM"},
    "UNKNOWN": {"actor": "Unattributed Foreign Endpoint", "threat_category": "External Network Probe", "risk_factor": "LOW"}
}

class ThreatIntelligenceEngine:
    def __init__(self):
        self.incident_reports = []
        self.escalated_sos = []

    def compute_sha256(self, data_bytes: bytes) -> str:
        """Compute local-first SHA-256 hash without remote leaks."""
        return hashlib.sha256(data_bytes).hexdigest()

    def geo_profile_request(self, req) -> dict:
        """
        Inspects headers and IP metadata to identify foreign threat actors,
        cross-border reconnaissance signatures, and anonymized proxies.
        """
        source_ip = req.headers.get('X-Forwarded-For', req.remote_addr or '127.0.0.1')
        if ',' in source_ip:
            source_ip = source_ip.split(',')[0].strip()

        # Check explicit or proxy-forwarded country headers
        country_code = (
            req.headers.get('CF-IPCountry') or
            req.headers.get('X-Country-Code') or
            req.headers.get('X-Geo-Country') or
            ""
        ).upper()

        user_agent = req.headers.get('User-Agent', 'Unknown / Raw Socket')

        # Heuristic geo-simulation if not provided by CDN/reverse-proxy
        is_foreign = False
        if not country_code:
            # Deterministic/heuristic classification based on IP patterns
            if source_ip.startswith("185.") or source_ip.startswith("194."):
                country_code = "RU"
                is_foreign = True
            elif source_ip.startswith("218.") or source_ip.startswith("221."):
                country_code = "CN"
                is_foreign = True
            elif source_ip.startswith("175.45."):
                country_code = "KP"
                is_foreign = True
            elif source_ip.startswith("109.201.") or "Tor" in user_agent:
                country_code = "TOR"
                is_foreign = True
            elif source_ip in ("127.0.0.1", "localhost") or source_ip.startswith("192.168.") or source_ip.startswith("10."):
                country_code = "LOCAL"
                is_foreign = False
            else:
                country_code = "US"
                is_foreign = False
        else:
            is_foreign = country_code not in ("US", "CA", "LOCAL")

        profile = KNOWN_FOREIGN_APT_ORIGINS.get(country_code, {
            "actor": f"Endpoint ({country_code})",
            "threat_category": "Standard Remote Traffic",
            "risk_factor": "LOW" if not is_foreign else "MEDIUM"
        })

        return {
            "source_ip": source_ip,
            "country_code": country_code,
            "is_foreign": is_foreign,
            "attributed_actor": profile["actor"],
            "threat_category": profile["threat_category"],
            "geo_risk": profile["risk_factor"],
            "user_agent": user_agent
        }

    def inspect_file_heuristics(self, content: str, raw_bytes: bytes) -> dict:
        """
        Deep heuristic and signature inspection of file/code content
        for malicious logic, script obfuscation, backdoors, and wiper commands.
        """
        c_lower = content.lower()
        findings = []
        mitre_tactics = []
        risk_score = 0

        # 1. Script Obfuscation & Evasion (T1027)
        if re.search(r'eval\s*\(\s*(base64_decode|gzinflate|str_rot13|unescape|atob)', c_lower):
            findings.append("Multi-stage Base64 / Gzip eval obfuscation wrapper detected")
            mitre_tactics.append("T1027: Obfuscated Files or Information")
            risk_score += 40

        if re.search(r'(fromcharcode|charcodeat|xor_cipher|payload_hex)', c_lower):
            findings.append("Character-code / XOR dynamic string reconstruction detected")
            mitre_tactics.append("T1027.001: Binary Padding / Dynamic String Decoding")
            risk_score += 25

        if len(re.findall(r'[A-Za-z0-9+/=]{80,}', content)) > 2:
            findings.append("Large embedded high-entropy Base64 blob detected")
            risk_score += 20

        # 2. Command Injection & Backdoors (T1059, T1071)
        if any(sig in c_lower for sig in ['/dev/tcp/', 'nc -e', 'mkfifo /tmp/', 'reverse_shell', 'socket.socket']):
            findings.append("Active Reverse Shell / Interactive TCP socket staging")
            mitre_tactics.append("T1059: Command and Scripting Interpreter")
            mitre_tactics.append("T1071: Standard Application Layer Protocol")
            risk_score += 50

        if any(sig in c_lower for sig in ['passthru(', 'shell_exec(', 'popen(', 'proc_open(', 'wscript.shell']):
            findings.append("Direct OS Shell Execution primitives")
            mitre_tactics.append("T1059: Command Execution")
            risk_score += 35

        # 3. Ransomware / Wiper / APT Destructive Logic (T1486, T1490)
        if any(sig in c_lower for sig in ['vssadmin delete shadows', 'bcdedit /set {default} bootstatuspolicy', 'wbadmin delete catalog']):
            findings.append("Volume Shadow Copy & Backup deletion commands detected (Ransomware Preparation)")
            mitre_tactics.append("T1490: Inhibit System Recovery")
            risk_score += 60

        if any(sig in c_lower for sig in ['cryptencrypt', 'rijndael', 'aes_gcm', 'ransom_note', '.locked', 'public_key_rsa']):
            findings.append("Bulk cryptographic file encryption routines identified")
            mitre_tactics.append("T1486: Data Encrypted for Impact")
            risk_score += 45

        # 4. Credential Harvesting & Mimikatz (T1003)
        if any(sig in c_lower for sig in ['sekurlsa::logonpasswords', 'mimikatz', 'lsass.dmp', 'procdump', '/etc/shadow']):
            findings.append("LSASS memory dumping or Shadow file credential extraction")
            mitre_tactics.append("T1003: OS Credential Dumping")
            risk_score += 55

        # Severity mapping
        if risk_score >= 70:
            severity = "CRITICAL"
        elif risk_score >= 40:
            severity = "HIGH"
        elif risk_score >= 20:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": min(100, risk_score),
            "severity": severity,
            "findings": findings if findings else ["No high-confidence malicious logic or obfuscation identified"],
            "mitre_tactics": list(set(mitre_tactics)) if mitre_tactics else ["T1036: Masquerading (Low anomaly)"],
            "is_clean": len(findings) == 0
        }

    def generate_incident_report(self, file_meta: dict, geo_meta: dict, analysis: dict) -> dict:
        """
        Compiles an executive JSON incident report complete with
        IoCs, Severity Level, and Actionable Remediation Guidance.
        """
        incident_id = f"AEGIS-INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        severity = analysis["severity"]

        # If foreign actor detected with high severity, elevate to CRITICAL
        if geo_meta.get("is_foreign") and geo_meta.get("geo_risk") in ("HIGH", "CRITICAL") and severity == "HIGH":
            severity = "CRITICAL"

        # Executive Summary
        if severity in ("HIGH", "CRITICAL"):
            summary = (
                f"Aegis-X intercepted a {severity.lower()} threat vector originating from {geo_meta['source_ip']} "
                f"({geo_meta['country_code']} - {geo_meta['attributed_actor']}). The payload exhibits "
                f"{len(analysis['findings'])} malicious indicators, including: {', '.join(analysis['findings'][:2])}."
            )
        elif severity == "MEDIUM":
            summary = (
                f"Suspicious script logic detected from {geo_meta['source_ip']} ({geo_meta['country_code']}). "
                f"File contains suspicious structures requiring sandbox containment."
            )
        else:
            summary = (
                f"Routine scan completed for {file_meta['filename']} from {geo_meta['source_ip']}. "
                f"No dangerous exploit logic or backdoors detected."
            )

        # Actionable Remediation Steps
        recommendations = []
        if severity == "CRITICAL":
            recommendations = [
                f"Immediately firewall and blacklist source IP {geo_meta['source_ip']} across perimeter border gateways.",
                "Isolate the affected workstation/endpoint from local VLAN and initiate forensic memory image.",
                "Revoke any active session tokens, domain credentials, and rotate API keys.",
                "Dispatch incident dossier to White-Hat SOC response team for active counter-measures."
            ]
        elif severity == "HIGH":
            recommendations = [
                f"Quarantine file with SHA-256 hash {file_meta['sha256']}.",
                "Inspect parent execution processes and check event logs for persistence artifacts.",
                "Verify host integrity against baseline system hashes."
            ]
        elif severity == "MEDIUM":
            recommendations = [
                "Execute sample in an isolated sandbox environment before executing in production.",
                "Monitor endpoint for unusual outbound TCP sockets."
            ]
        else:
            recommendations = [
                "File deemed safe for standard workstation operations.",
                "Standard telemetry retention applied."
            ]

        report = {
            "incident_id": incident_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "short_summary": summary,
            "severity": severity,
            "indicators_of_compromise": {
                "sha256": file_meta["sha256"],
                "file_name": file_meta["filename"],
                "file_size_bytes": file_meta["size"],
                "source_ip": geo_meta["source_ip"],
                "country_code": geo_meta["country_code"],
                "threat_actor_attribution": geo_meta["attributed_actor"],
                "matched_signatures": analysis["findings"]
            },
            "mitre_attack_tactics": analysis["mitre_tactics"],
            "recommended_actions": recommendations,
            "telemetry_metadata": {
                "geo_profiling": geo_meta,
                "risk_score": analysis["risk_score"]
            }
        }

        self.incident_reports.append(report)
        return report

    def evaluate_escalation(self, report: dict, consent: bool, user_escalation_auth: bool) -> dict:
        """
        Decision-routing workflow:
        If severity is HIGH or CRITICAL and user provides explicit authorization,
        package the incident report and route to White-Hat SOC responders.
        """
        severity = report["severity"]
        is_elevated_severity = severity in ("HIGH", "CRITICAL")
        authorized = consent and user_escalation_auth

        if is_elevated_severity and authorized:
            dispatch_ticket = {
                "ticket_id": f"SOC-DISPATCH-{uuid.uuid4().hex[:8].upper()}",
                "incident_id": report["incident_id"],
                "dispatched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "DISPATCHED_TO_WHITE_HAT_SOC",
                "priority": "P1_URGENT" if severity == "CRITICAL" else "P2_ELEVATED",
                "routing_target": "Aegis-X 24/7 Rapid Response SOC & Counter-Deception Unit",
                "incident_report": report
            }
            self.escalated_sos.append(dispatch_ticket)
            return {
                "escalation_status": "ESCALATED",
                "message": "Incident report successfully packaged and routed to White-Hat SOC Responders.",
                "dispatch_ticket": dispatch_ticket
            }
        elif is_elevated_severity and not authorized:
            return {
                "escalation_status": "PENDING_AUTHORIZATION",
                "message": (
                    f"Threat severity is {severity}, but escalation to White-Hat SOC was held "
                    "because explicit user authorization ('escalation_authorized: true') was not granted."
                ),
                "dispatch_ticket": None
            }
        else:
            return {
                "escalation_status": "NOT_REQUIRED",
                "message": f"Threat severity is {severity}; White-Hat SOC escalation threshold not triggered.",
                "dispatch_ticket": None
            }


# Singleton Engine Instance
threat_intel_engine = ThreatIntelligenceEngine()

# Flask Blueprint
threat_intel_bp = Blueprint('threat_intel_bp', __name__)

@threat_intel_bp.route('/api/v1/analyze_file', methods=['POST', 'OPTIONS'])
def analyze_file():
    """
    User-Consent File Analysis Engine
    Endpoint: POST /api/v1/analyze_file
    Requires:
      - consent: true (via JSON, Form, or X-User-Consent header)
      - file / payload / script content
    """
    if request.method == 'OPTIONS':
        return Response(status=200)

    # 1. Verify Explicit User Consent
    consent = False
    escalation_auth = False
    raw_content = ""
    filename = "analyzed_artifact.txt"
    raw_bytes = b""

    # Check JSON request
    if request.is_json:
        req_json = request.get_json(silent=True) or {}
        consent = req_json.get('consent') is True
        escalation_auth = req_json.get('authorize_escalation') is True or req_json.get('escalation_authorized') is True
        raw_content = req_json.get('content') or req_json.get('payload') or req_json.get('file') or ""
        filename = req_json.get('filename') or filename
        raw_bytes = raw_content.encode('utf-8', errors='replace')

    # Check Form / Multipart request
    elif request.form or request.files:
        consent = request.form.get('consent', '').lower() in ('true', '1', 'yes')
        escalation_auth = request.form.get('authorize_escalation', '').lower() in ('true', '1', 'yes')
        
        if 'file' in request.files:
            file_obj = request.files['file']
            filename = file_obj.filename or filename
            raw_bytes = file_obj.read(MAX_FILE_SIZE)
            raw_content = raw_bytes.decode('utf-8', errors='replace')
        elif 'content' in request.form:
            raw_content = request.form.get('content', '')
            raw_bytes = raw_content.encode('utf-8', errors='replace')

    # Check header fallback for consent
    if not consent:
        header_consent = request.headers.get('X-User-Consent', '').lower()
        consent = header_consent in ('true', '1', 'yes')

    # Check header fallback for escalation
    if not escalation_auth:
        header_auth = request.headers.get('X-Authorize-Escalation', '').lower()
        escalation_auth = header_auth in ('true', '1', 'yes')

    # MANDATORY CONSENT CHECK
    if not consent:
        return jsonify({
            "status": "CONSENT_REQUIRED",
            "error": "Explicit user consent is mandatory for telemetry analysis and transmission.",
            "code": 403,
            "instruction": "Set 'consent: true' in request payload or provide 'X-User-Consent: true' header."
        }), 403

    if not raw_bytes:
        # Fallback to request raw data
        raw_bytes = request.get_data(cache=False, as_text=False)[:MAX_FILE_SIZE]
        raw_content = raw_bytes.decode('utf-8', errors='replace')

    if not raw_bytes:
        return jsonify({
            "status": "error",
            "error": "No file content or code snippet provided for analysis."
        }), 400

    # 2. Local-First SHA-256 Hashing
    sha256_hash = threat_intel_engine.compute_sha256(raw_bytes)
    file_meta = {
        "filename": filename,
        "size": len(raw_bytes),
        "sha256": sha256_hash,
        "sha256_short": f"{sha256_hash[:16]}...{sha256_hash[-8:]}"
    }

    # 3. Foreign Attack Detection & Geo-Profiling
    geo_meta = threat_intel_engine.geo_profile_request(request)

    # 4. Deep Heuristic & Signature Inspection
    analysis_result = threat_intel_engine.inspect_file_heuristics(raw_content, raw_bytes)

    # 5. Structured Incident Report Generation
    incident_report = threat_intel_engine.generate_incident_report(file_meta, geo_meta, analysis_result)

    # 6. User Consent & White-Hat Escalation Workflow
    escalation_result = threat_intel_engine.evaluate_escalation(
        incident_report,
        consent=consent,
        user_escalation_auth=escalation_auth
    )

    # 7. Record Telemetry in Global Mastermind Threat Log
    try:
        from server import threat_log, sos_alerts, broadcast_event
        tier = "TIER_3" if incident_report["severity"] == "CRITICAL" else ("TIER_2" if incident_report["severity"] == "HIGH" else "TIER_1")
        if analysis_result["is_clean"]:
            tier = "SAFE"

        threat_entry = {
            "id": incident_report["incident_id"],
            "time": datetime.now().strftime("%H:%M:%S"),
            "timestamp": incident_report["timestamp"],
            "tier": tier,
            "action": "WHITE-HAT ESCALATED" if escalation_result["escalation_status"] == "ESCALATED" else ("ANALYSIS COMPLETE" if analysis_result["is_clean"] else "INCIDENT LOGGED"),
            "reason": f"File: {filename} [{incident_report['severity']}] - {geo_meta['country_code']} ({geo_meta['attributed_actor']})",
            "poison": f"Escalation: {escalation_result['escalation_status']}" if escalation_result["escalation_status"] == "ESCALATED" else "",
            "sha256": sha256_hash,
            "sha256_short": file_meta["sha256_short"],
            "source_ip": geo_meta["source_ip"],
            "incident_report": incident_report
        }
        threat_log.append(threat_entry)
        broadcast_event(threat_entry)

        if escalation_result["escalation_status"] == "ESCALATED":
            sos_alerts.append(escalation_result["dispatch_ticket"])
    except Exception:
        pass

    return jsonify({
        "status": "SUCCESS",
        "file_metadata": file_meta,
        "geo_profile": geo_meta,
        "analysis": analysis_result,
        "incident_report": incident_report,
        "escalation": escalation_result
    }), 200

@threat_intel_bp.route('/api/v1/incidents', methods=['GET'])
def get_incidents():
    """Returns all structured incident reports."""
    return jsonify({
        "total_incidents": len(threat_intel_engine.incident_reports),
        "incidents": threat_intel_engine.incident_reports[-50:]
    }), 200

@threat_intel_bp.route('/api/v1/incidents/<incident_id>/authorize_escalation', methods=['POST'])
def authorize_incident_escalation(incident_id):
    """
    Explicit authorization endpoint to approve routing a pending high/critical
    incident report to the White-Hat SOC response team.
    """
    for report in threat_intel_engine.incident_reports:
        if report["incident_id"] == incident_id:
            escalation = threat_intel_engine.evaluate_escalation(report, consent=True, user_escalation_auth=True)
            return jsonify({
                "status": "SUCCESS",
                "incident_id": incident_id,
                "escalation": escalation
            }), 200

    return jsonify({"status": "error", "message": f"Incident {incident_id} not found"}), 404


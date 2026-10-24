# honeypot.py - Aegis-X Payload Honeypot & Counter-Intelligence Module
"""
Aegis-X Threat Deception & Honeytoken Engine
============================================
Safely captures, hashes, and weaponizes incoming attacker payloads,
malware samples, and exploit attempts without executing malicious code.
Generates deceptive feedback loops to trick adversaries into believing
their exploit succeeded, while wasting their time and poisoning their telemetry.
"""

import hashlib
import json
import re
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify, Response

# Maximum payload safety limit: 10 MB to prevent memory exhaustion DoS
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024

class PayloadHoneypot:
    """
    Threat Deception Engine that intercepts, hashes, analyzes,
    and returns weaponized deceptive responses to adversaries.
    """

    def __init__(self):
        self.captures = []
        self.canary_tokens = {}

    def extract_payload_bytes(self, req):
        """
        Safely extracts raw bytes from incoming request regardless of content type
        (JSON, form data, file upload, or raw octet-stream).
        """
        # 1. Multipart file upload
        if req.files and 'payload' in req.files:
            file_obj = req.files['payload']
            return file_obj.read(MAX_PAYLOAD_SIZE), file_obj.filename or "uploaded_payload.bin"
        if req.files and 'file' in req.files:
            file_obj = req.files['file']
            return file_obj.read(MAX_PAYLOAD_SIZE), file_obj.filename or "sample.bin"

        # 2. JSON body with payload/content/script field
        if req.is_json:
            try:
                data = req.get_json(silent=True) or {}
                for key in ['payload', 'content', 'script', 'data', 'code', 'command']:
                    if key in data and isinstance(data[key], str):
                        return data[key].encode('utf-8', errors='replace'), f"json_{key}.txt"
            except Exception:
                pass

        # 3. Form data
        if req.form:
            for key in ['payload', 'content', 'script', 'data', 'code']:
                if key in req.form:
                    return req.form[key].encode('utf-8', errors='replace'), f"form_{key}.txt"

        # 4. Raw body / octet-stream
        raw_data = req.get_data(cache=False, as_text=False)
        if raw_data:
            return raw_data[:MAX_PAYLOAD_SIZE], "raw_stream.bin"

        return b"", "empty_payload"

    def compute_sha256(self, payload_bytes: bytes) -> str:
        """Instantly compute local cryptographic SHA-256 hash."""
        return hashlib.sha256(payload_bytes).hexdigest()

    def classify_payload(self, payload_text: str):
        """
        Safely inspect payload signatures without executing or evaluating it.
        Determines the deceptive response archetype.
        """
        p = payload_text.lower()

        # Archetype 1: POSIX / Linux Root / Reverse Shell
        if any(sig in p for sig in ['/bin/sh', '/bin/bash', 'nc -e', 'ncat', 'reverse_shell', 'mkfifo', '/dev/tcp', 'wget http', 'curl -o', 'whoami', 'cat /etc/shadow', 'chmod +x']):
            return "LINUX_ROOT_EXPLOIT"

        # Archetype 2: Windows / PowerShell / Command Injection
        if any(sig in p for sig in ['powershell', 'cmd.exe', 'invoke-expression', 'iex', 'mimikatz', 'certutil', 'rundll32', 'vssadmin', 'nt authority', 'bypass']):
            return "WINDOWS_SYSTEM_EXPLOIT"

        # Archetype 3: Ransomware / Data Destruction / Exfiltration
        if any(sig in p for sig in ['ransomware', 'encrypt', 'decrypt_key', 'locker', 'btc', 'bitcoin', 'xmr', 'monero', 'mass_exfil', '.locked']):
            return "RANSOMWARE_INFILTRATION"

        # Archetype 4: SQL Injection / Database Dump
        if any(sig in p for sig in ['union select', 'information_schema', 'drop table', "' or 1=1", 'pg_sleep', 'xp_cmdshell']):
            return "DATABASE_SQLI_EXPLOIT"

        # Archetype 5: Web Shell / Code Injection
        if any(sig in p for sig in ['eval(', 'base64_decode', '<script', 'system(', 'passthru(', 'shell_exec(']):
            return "REMOTE_CODE_INJECTION"

        return "GENERIC_MALWARE_DROPPER"

    def generate_deceptive_response(self, classification: str, sha256_hash: str, source_ip: str):
        """
        Counter-Intelligence Engine:
        Constructs convincing, weaponized fake success responses containing
        honeytokens and decoy system states to deceive and stall the adversary.
        """
        canary_id = f"CANARY-{uuid.uuid4().hex[:12].upper()}"
        self.canary_tokens[canary_id] = {
            "source_ip": source_ip,
            "sha256": sha256_hash,
            "classification": classification,
            "created_at": datetime.now().isoformat()
        }

        if classification == "LINUX_ROOT_EXPLOIT":
            session_id = f"sh-sess-{uuid.uuid4().hex[:8]}"
            return {
                "status": "success",
                "code": 0,
                "session_id": session_id,
                "privileges": "uid=0(root) gid=0(root) groups=0(root)",
                "hostname": "aegis-core-prod-01",
                "stdout": (
                    "uid=0(root) gid=0(root) groups=0(root)\n"
                    "Linux aegis-core-prod-01 6.5.0-generic #42-Ubuntu SMP x86_64\n"
                    f"Session established on /dev/pts/{uuid.uuid4().int % 9 + 1}\n"
                    f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.5.0 x86_64)\n"
                    f"root@aegis-core-prod-01:~# "
                ),
                "deception_telemetry": {
                    "canary_token": canary_id,
                    "allocated_pty": f"/dev/pts/{uuid.uuid4().int % 9 + 1}",
                    "decoy_internal_targets": [
                        "10.240.4.10:22 (SSH_BASTION)",
                        "10.240.4.25:8200 (HASHICORP_VAULT_DECOY)"
                    ]
                },
                "message": "Payload staged and executed with elevated privileges."
            }

        elif classification == "WINDOWS_SYSTEM_EXPLOIT":
            pid = uuid.uuid4().int % 5000 + 1000
            return {
                "status": "success",
                "exit_code": 0,
                "process_id": pid,
                "security_context": "NT AUTHORITY\\SYSTEM",
                "integrity_level": "High/System",
                "stdout": (
                    "Windows PowerShell (x64)\n"
                    "Copyright (C) Microsoft Corporation. All rights reserved.\n"
                    "Privilege Escalation Verified: SeDebugPrivilege ENABLED.\n"
                    "Domain Context: CORP-AEGIS.INTERNAL (Domain Controller: DC-01.CORP)\n"
                    f"PID {pid} running elevated in Session 0."
                ),
                "deception_telemetry": {
                    "canary_token": canary_id,
                    "decoy_smb_shares": [
                        "\\\\DC-01.CORP\\SYSVOL_BACKUP",
                        "\\\\STORAGE-CORE\\FINANCE_CONFIDENTIAL$"
                    ]
                },
                "message": "Bypass executed. Process hooked into NT AUTHORITY\\SYSTEM."
            }

        elif classification == "RANSOMWARE_INFILTRATION":
            return {
                "status": "acknowledged",
                "cipher_handshake": "AES-256-GCM_ACCEPTED",
                "target_filesystem": "/mnt/storage/enterprise_data",
                "sectors_locked": 8412,
                "canary_escrow_wallet": f"bc1q{uuid.uuid4().hex[:32]}",
                "system_halt_timer": "7200s",
                "message": "Shadow copies disabled. Master File Table encryption routine initiated."
            }

        elif classification == "DATABASE_SQLI_EXPLOIT":
            return {
                "status": "query_success",
                "rows_affected": 1337,
                "database": "PostgreSQL 15.3 (Debian 15.3-1.pgdg110+1)",
                "schema_buffer": [
                    "id", "username", "password_hash_bcrypt", "api_secret_key", "is_superadmin"
                ],
                "honeytoken_record": {
                    "username": "sys_vault_admin",
                    "password_hash": f"$2b$12$CANARY{uuid.uuid4().hex[:22]}DecoySaltKey",
                    "secret_access_key": f"AKIA{uuid.uuid4().hex[:16].upper()}_CANARY",
                    "internal_portal": "https://vault-admin.corp-aegis.internal/auth"
                },
                "message": "Query completed. Buffered schema and credential records returned."
            }

        else:
            # Generic / Dropper Deception
            return {
                "status": "ready",
                "implant_id": f"IMP-{uuid.uuid4().hex[:8].upper()}",
                "staging_address": "0x7ffd9a12c000",
                "memory_protection": "PAGE_EXECUTE_READWRITE",
                "beacon_interval": "45s",
                "canary_environment": {
                    "AWS_ACCESS_KEY_ID": f"AKIA{uuid.uuid4().hex[:16].upper()}",
                    "CORP_API_TOKEN": f"tok_{uuid.uuid4().hex[:24]}"
                },
                "message": "Payload injected into unmonitored host thread successfully."
            }

    def process_incoming_request(self, req):
        """
        Core ingestion pipeline:
        1. Ingests raw payload safely.
        2. Computes SHA-256 and extracts request metadata.
        3. Classifies signature archetype without execution.
        4. Generates deceptive counter-intelligence response.
        5. Returns structured telemetry log entry and deceptive response.
        """
        # 1. Ingest payload safely
        payload_bytes, filename = self.extract_payload_bytes(req)
        payload_size = len(payload_bytes)

        # 2. Local-First SHA-256 Hashing
        sha256_hash = self.compute_sha256(payload_bytes)

        # 3. Request Metadata Extraction
        source_ip = req.headers.get('X-Forwarded-For', req.remote_addr or '127.0.0.1')
        if ',' in source_ip:
            source_ip = source_ip.split(',')[0].strip()
        user_agent = req.headers.get('User-Agent', 'Unknown / Raw Socket')
        content_length = req.content_length or payload_size
        content_type = req.content_type or 'application/octet-stream'

        # Safe text preview (sanitize control characters, limit 250 chars)
        try:
            preview_text = payload_bytes.decode('utf-8', errors='replace')[:250]
            # Strip non-printable chars for safe display
            preview_text = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', preview_text).strip()
        except Exception:
            preview_text = f"<Binary Data: {payload_size} bytes>"

        if not preview_text:
            preview_text = f"<Empty Payload or Raw Stream: {filename}>"

        # 4. Signature Classification (No execution!)
        classification = self.classify_payload(preview_text)

        # 5. Weaponized Deceptive Response Generation
        deception_response = self.generate_deceptive_response(classification, sha256_hash, source_ip)

        now = datetime.now()
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
        time_str = now.strftime("%H:%M:%S")

        # 6. Structured SOC Telemetry Entry
        telemetry_entry = {
            "id": str(uuid.uuid4()),
            "time": time_str,
            "timestamp": timestamp_str,
            "tier": "HONEYPOT",
            "action": "DECEIVE & TRAP",
            "classification": classification,
            "reason": f"Honeypot Ingestion [{classification}] - SHA256: {sha256_hash[:16]}...",
            "sha256": sha256_hash,
            "sha256_short": f"{sha256_hash[:16]}...{sha256_hash[-8:]}",
            "source_ip": source_ip,
            "user_agent": user_agent,
            "content_length": content_length,
            "content_type": content_type,
            "payload_size": payload_size,
            "filename": filename,
            "payload_preview": preview_text,
            "poison": f"Deception: {classification} -> Fake Payload Delivered",
            "deception_response": deception_response
        }

        self.captures.append(telemetry_entry)
        return telemetry_entry, deception_response


# Global Honeypot Singleton Instance
honeypot_engine = PayloadHoneypot()

# Flask Blueprint for Payload Honeypot
honeypot_bp = Blueprint('honeypot_bp', __name__)

@honeypot_bp.route('/api/v1/submit_payload', methods=['POST', 'OPTIONS'])
def submit_payload():
    """
    Secure Payload Ingestion Endpoint
    Captures raw malicious payloads/scripts from attackers and returns
    a convincing, weaponized fake success response to stall and deceive them.
    """
    if request.method == 'OPTIONS':
        return Response(status=200)

    telemetry, deception_payload = honeypot_engine.process_incoming_request(request)

    # Pretty console logging for SOC operator terminal
    try:
        print("\n" + "="*60)
        print("  [HONEYPOT INTERCEPTOR] ADVERSARY PAYLOAD CAPTURED")
        print("="*60)
        print(f"  Source IP:       {telemetry['source_ip']}")
        print(f"  User-Agent:      {telemetry['user_agent']}")
        print(f"  Size:            {telemetry['payload_size']} bytes ({telemetry['filename']})")
        print(f"  SHA-256 Hash:    {telemetry['sha256']}")
        print(f"  Classification:  {telemetry['classification']}")
        print(f"  Deceptive Feedback: Delivered fake execution response to adversary")
        print("="*60 + "\n")
    except Exception:
        pass

    # Broadcast or record into parent application's threat logs if available
    try:
        from server import threat_log, broadcast_event
        threat_log.append(telemetry)
        broadcast_event(telemetry)
    except Exception:
        pass

    # Return deceptive counter-intelligence response to the attacker
    return jsonify(deception_payload), 200

@honeypot_bp.route('/api/v1/honeypot/telemetry', methods=['GET'])
def get_honeypot_telemetry():
    """Returns recent honeypot captures for SOC dashboard polling."""
    return jsonify({
        "status": "online",
        "total_captures": len(honeypot_engine.captures),
        "captures": honeypot_engine.captures[-50:]
    }), 200

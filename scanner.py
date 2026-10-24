# scanner.py - Aegis-X Deterministic Malware & Threat Analysis Engine
"""
Aegis-X Deterministic Malware & Threat Analysis Engine
======================================================
Strictly deterministic, explainable security analysis without LLMs, ML models,
or external network dependencies. Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

# ---------------------------------------------------------------------------
# Configuration & Thresholds
# ---------------------------------------------------------------------------

CONFIG: Dict[str, Any] = {
    "verdict_thresholds": {
        "safe_max": 29.9,
        "suspicious_max": 69.9,
        "dangerous_min": 70.0,
    },
    "verdict_colors": {
        "SAFE": "emerald",
        "SUSPICIOUS": "amber",
        "DANGEROUS": "red",
    },
    "max_file_size": 10 * 1024 * 1024,  # 10 MB
    "entropy_block_size": 4096,         # 4 KB blocks
    "high_entropy_threshold": 7.2,       # Shannon entropy threshold (bits/byte)
    "known_bad_hashes_file": "known_bad_hashes.json",
}

# Target Brands for Typosquatting / Damerau-Levenshtein Analysis
TARGET_BRANDS: List[str] = [
    "google", "paypal", "amazon", "apple", "microsoft", "netflix",
    "facebook", "bankofamerica", "chase", "wellsfargo", "coinbase",
    "binance", "instagram", "twitter", "github", "linkedin", "dropbox"
]

# High-Risk / Suspicious Top-Level Domains (TLDs)
RISKY_TLDS: set[str] = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "fit", "buzz",
    "work", "cn", "ru", "cc", "monster", "rest", "cam", "kim"
}

# Known URL Shorteners
URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "goo.gl", "rebrand.ly", "qr.net", "v.gd"
}

# Leetspeak / Visual Substitution Mapping
LEET_MAP: Dict[str, str] = {
    "0": "o", "1": "l", "!": "i", "3": "e", "4": "a",
    "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"
}

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    category: str
    description: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    score_impact: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EntropyBlock:
    offset: int
    size: int
    entropy: float
    is_high: bool


@dataclass
class EntropyResult:
    overall_entropy: float
    block_size: int
    total_blocks: int
    high_entropy_blocks: int
    is_packed_or_encrypted: bool
    findings: List[Finding] = field(default_factory=list)


@dataclass
class LinkScanResult:
    url: str
    score: float
    verdict: str
    verdict_color: str
    hostname: str
    findings: List[Finding] = field(default_factory=list)


@dataclass
class MessageScanResult:
    message: str
    score: float
    verdict: str
    verdict_color: str
    urls_found: List[str]
    link_results: List[LinkScanResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


@dataclass
class PasswordResult:
    password_masked: str
    score: float  # 0 to 100 strength score
    verdict: str
    verdict_color: str
    entropy_bits: float
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    target_type: str
    score: float
    verdict: str
    verdict_color: str
    reasons: List[str]
    hash_sha256: str
    timestamp: str
    request_id: str
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def final_verdict(score: float) -> Tuple[str, str]:
    """
    Pure function mapping a 0-100 score to (verdict, color).
    Thresholds:
      Score < 30   -> SAFE (emerald)
      Score 30-69  -> SUSPICIOUS (amber)
      Score >= 70  -> DANGEROUS (red)
    """
    score_clamped = max(0.0, min(100.0, float(score)))
    thresholds = CONFIG["verdict_thresholds"]
    colors = CONFIG["verdict_colors"]

    if score_clamped <= thresholds["safe_max"]:
        return "SAFE", colors["SAFE"]
    if score_clamped <= thresholds["suspicious_max"]:
        return "SUSPICIOUS", colors["SUSPICIOUS"]
    return "DANGEROUS", colors["DANGEROUS"]


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Compute Damerau-Levenshtein distance between two strings,
    supporting insertion, deletion, substitution, and adjacent transposition.
    """
    len1, len2 = len(s1), len(s2)
    d: Dict[Tuple[int, int], int] = {}

    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            # Transposition check
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

    return d[(len1 - 1, len2 - 1)]


def normalize_leetspeak(s: str) -> str:
    """Replaces common visual substitutions with their base characters."""
    result = []
    for char in s.lower():
        result.append(LEET_MAP.get(char, char))
    return "".join(result)


# ---------------------------------------------------------------------------
# Core Analysis Routines
# ---------------------------------------------------------------------------

# 1. Known Bad Hash Lookup (Hot-Reloadable)
_hash_registry_cache: Dict[str, Any] = {}
_hash_file_mtime: float = 0.0

def load_known_bad_hashes() -> Dict[str, Any]:
    """Loads known bad hashes from disk with hot-reload support."""
    global _hash_registry_cache, _hash_file_mtime
    filepath = CONFIG["known_bad_hashes_file"]
    if not os.path.exists(filepath):
        return {}

    try:
        current_mtime = os.path.getmtime(filepath)
        if current_mtime != _hash_file_mtime or not _hash_registry_cache:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                _hash_registry_cache = data.get("hashes", {})
                _hash_file_mtime = current_mtime
    except Exception:
        pass
    return _hash_registry_cache


def file_hash(data: bytes) -> Tuple[str, Optional[Finding]]:
    """
    Computes local SHA-256 hash and checks against local known-bad hash registry.
    """
    sha256 = hashlib.sha256(data).hexdigest()
    bad_hashes = load_known_bad_hashes()

    if sha256 in bad_hashes:
        info = bad_hashes[sha256]
        finding = Finding(
            category="KNOWN_MALWARE_HASH",
            description=f"Matched known malicious malware signature: {info.get('malware_family', 'Generic Threat')}",
            severity="CRITICAL",
            score_impact=float(info.get("score", 100.0)),
        )
        return sha256, finding

    return sha256, None


# 2. File Type & Extension Validation
MAGIC_SIGNATURES: List[Tuple[bytes, str, List[str]]] = [
    (b"%PDF-", "PDF Document", [".pdf"]),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", [".png"]),
    (b"\xff\xd8\xff", "JPEG Image", [".jpg", ".jpeg"]),
    (b"GIF87a", "GIF Image", [".gif"]),
    (b"GIF89a", "GIF Image", [".gif"]),
    (b"PK\x03\x04", "ZIP / OOXML Archive", [".zip", ".docx", ".xlsx", ".apk", ".jar"]),
    (b"MZ", "Windows PE Executable / DLL", [".exe", ".dll", ".sys", ".scr"]),
    (b"\x7fELF", "Linux ELF Binary", [".elf", ".bin", ""]),
    (b"#!/", "Unix Shell Script", [".sh", ".bash", ".py", ".pl"]),
]

def check_file_type(filename: str, data: bytes) -> List[Finding]:
    """
    Validates magic bytes against extension, detects double extensions,
    RTLO (Right-to-Left Override) attacks, and null byte injections.
    """
    findings: List[Finding] = []
    clean_name = filename.strip()

    # Check 1: Right-to-Left Override (RTLO) Attack (\u202e)
    if "\u202e" in clean_name or "\u202E" in clean_name:
        findings.append(Finding(
            category="RTLO_OBFUSCATION",
            description="Filename contains Right-to-Left Override Unicode character (U+202E) to disguise file extension",
            severity="CRITICAL",
            score_impact=90.0
        ))

    # Check 2: Null Byte Injection
    if "\x00" in clean_name or "%00" in clean_name:
        findings.append(Finding(
            category="NULL_BYTE_INJECTION",
            description="Filename contains null byte injection sequence",
            severity="HIGH",
            score_impact=50.0
        ))

    # Check 3: Double Extensions (e.g. invoice.pdf.exe)
    parts = clean_name.lower().split(".")
    if len(parts) > 2:
        penultimate = parts[-2]
        ultimate = parts[-1]
        executable_exts = {"exe", "scr", "bat", "cmd", "vbs", "ps1", "js", "jar", "pif", "hta"}
        decoy_exts = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}
        if penultimate in decoy_exts and ultimate in executable_exts:
            findings.append(Finding(
                category="DOUBLE_EXTENSION",
                description=f"Double extension masquerade detected: '.{penultimate}.{ultimate}'",
                severity="HIGH",
                score_impact=60.0
            ))

    # Check 4: Magic-Byte vs Extension Mismatch
    ext = os.path.splitext(clean_name)[1].lower()
    detected_type: Optional[str] = None
    expected_exts: List[str] = []

    for magic, desc, valid_exts in MAGIC_SIGNATURES:
        if data.startswith(magic):
            detected_type = desc
            expected_exts = valid_exts
            break

    if detected_type and expected_exts:
        # Check if declared extension contradicts detected binary
        if ext and (ext not in expected_exts):
            # Severe: Executable disguised as document/image
            if "Executable" in detected_type or "ELF" in detected_type:
                findings.append(Finding(
                    category="EXTENSION_MISMATCH_EXECUTABLE",
                    description=f"Critical mismatch: Executable ({detected_type}) disguised with '{ext}' extension",
                    severity="CRITICAL",
                    score_impact=85.0
                ))
            else:
                findings.append(Finding(
                    category="EXTENSION_MISMATCH",
                    description=f"File extension '{ext}' does not match detected format '{detected_type}'",
                    severity="MEDIUM",
                    score_impact=35.0
                ))

    return findings


# 3. PDF Static Heuristic Scanner
PDF_INDICATORS: List[Tuple[re.Pattern, str, str, float]] = [
    (re.compile(rb"/JavaScript\b", re.IGNORECASE), "Embedded JavaScript (/JavaScript)", "HIGH", 35.0),
    (re.compile(rb"/JS\b", re.IGNORECASE), "Embedded JavaScript shorthand (/JS)", "HIGH", 30.0),
    (re.compile(rb"/OpenAction\b", re.IGNORECASE), "Auto-execution on document open (/OpenAction)", "HIGH", 30.0),
    (re.compile(rb"/AA\b", re.IGNORECASE), "Additional auto-execution actions (/AA)", "MEDIUM", 25.0),
    (re.compile(rb"/Launch\b", re.IGNORECASE), "External binary launcher directive (/Launch)", "CRITICAL", 45.0),
    (re.compile(rb"/EmbeddedFile\b", re.IGNORECASE), "Embedded binary payload attachment (/EmbeddedFile)", "MEDIUM", 20.0),
    (re.compile(rb"/SubmitForm\b", re.IGNORECASE), "Credential/Data submission directive (/SubmitForm)", "MEDIUM", 20.0),
    (re.compile(rb"/RichMedia\b", re.IGNORECASE), "RichMedia / Flash object payload container (/RichMedia)", "MEDIUM", 20.0),
    (re.compile(rb"/URI\b", re.IGNORECASE), "External URI link action (/URI)", "LOW", 10.0),
]

PDF_OBFUSCATION_INDICATORS: List[Tuple[re.Pattern, str, str, float]] = [
    (re.compile(rb"/#[0-9a-fA-F]{2}"), "Hex-escaped PDF name dictionary token obfuscation", "HIGH", 25.0),
    (re.compile(rb"/Filter\s*\[\s*(/[a-zA-Z0-9]+\s*){2,}\]"), "Chained multiple encoding filters (Filter Chain)", "HIGH", 30.0),
    (re.compile(rb"/ObjStm\b"), "Object stream container concealing sub-objects (/ObjStm)", "LOW", 10.0),
]

def scan_pdf(data: bytes, filename: str = "document.pdf") -> ScanResult:
    """
    Parses PDF bytes for exploit indicators, auto-actions, embedded scripts,
    and structural obfuscation without executing code.
    """
    findings: List[Finding] = []
    reasons: List[str] = []
    total_score = 0.0

    # Verify PDF magic bytes
    if not data.startswith(b"%PDF-"):
        findings.append(Finding(
            category="INVALID_PDF_HEADER",
            description="File lacks valid '%PDF-' header marker",
            severity="MEDIUM",
            score_impact=20.0
        ))

    # Evaluate Hash
    sha256, hash_finding = file_hash(data)
    if hash_finding:
        findings.append(hash_finding)
        reasons.append(hash_finding.description)
        total_score += hash_finding.score_impact

    # Evaluate Type/Extension Mismatches
    type_findings = check_file_type(filename, data)
    for tf in type_findings:
        findings.append(tf)
        reasons.append(tf.description)
        total_score += tf.score_impact

    # Evaluate Structural Indicators
    has_js = False
    has_auto_open = False

    for pattern, desc, severity, impact in PDF_INDICATORS:
        matches = len(pattern.findall(data))
        if matches > 0:
            if "JavaScript" in desc or "/JS" in desc:
                has_js = True
            if "OpenAction" in desc or "/AA" in desc:
                has_auto_open = True
            finding = Finding(
                category="PDF_SUSPICIOUS_KEYWORD",
                description=f"{desc} (Count: {matches})",
                severity=severity,
                score_impact=impact
            )
            findings.append(finding)
            reasons.append(finding.description)
            total_score += impact

    # Compound Threat check: JavaScript + OpenAction combined
    if has_js and has_auto_open:
        compound = Finding(
            category="PDF_DRIVEBY_SIGNATURE",
            description="High-Confidence Drive-By Exploit: Automatic execution with embedded JavaScript",
            severity="CRITICAL",
            score_impact=25.0
        )
        findings.append(compound)
        reasons.append(compound.description)
        total_score += 25.0

    # Evaluate Obfuscation Indicators
    for pattern, desc, severity, impact in PDF_OBFUSCATION_INDICATORS:
        matches = len(pattern.findall(data))
        if matches > 0:
            finding = Finding(
                category="PDF_OBFUSCATION",
                description=f"{desc} (Count: {matches})",
                severity=severity,
                score_impact=impact
            )
            findings.append(finding)
            reasons.append(finding.description)
            total_score += impact

    # Evaluate Entropy
    ent_res = file_entropy(data)
    if ent_res.is_packed_or_encrypted:
        findings.extend(ent_res.findings)
        for ef in ent_res.findings:
            reasons.append(ef.description)
            total_score += ef.score_impact

    clamped_score = min(100.0, round(total_score, 1))
    verdict, color = final_verdict(clamped_score)

    return ScanResult(
        target=filename,
        target_type="pdf",
        score=clamped_score,
        verdict=verdict,
        verdict_color=color,
        reasons=reasons if reasons else ["Clean PDF structure. No suspicious directives or script objects detected."],
        hash_sha256=sha256,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        request_id=f"SCAN-PDF-{sha256[:8].upper()}",
        findings=findings,
        metadata={"file_size": len(data), "overall_entropy": ent_res.overall_entropy}
    )


# 4. Shannon Entropy Calculator (Whole File & 4KB Blocks)
def calculate_shannon_entropy(chunk: bytes) -> float:
    """Calculates Shannon entropy in bits per byte [0.0 - 8.0]."""
    if not chunk:
        return 0.0
    byte_counts = [0] * 256
    for b in chunk:
        byte_counts[b] += 1
    total = len(chunk)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def file_entropy(data: bytes) -> EntropyResult:
    """
    Computes Shannon entropy over the entire file and per 4KB block,
    flagging packed or encrypted malicious regions.
    """
    overall = calculate_shannon_entropy(data)
    block_size = CONFIG["entropy_block_size"]
    threshold = CONFIG["high_entropy_threshold"]

    total_blocks = math.ceil(len(data) / block_size) if data else 1
    high_entropy_blocks = 0
    findings: List[Finding] = []

    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        chunk_entropy = calculate_shannon_entropy(chunk)
        if chunk_entropy >= threshold:
            high_entropy_blocks += 1

    is_packed = (overall >= threshold) or (high_entropy_blocks > 0 and len(data) > 8192)

    if overall >= threshold:
        findings.append(Finding(
            category="HIGH_FILE_ENTROPY",
            description=f"File exhibits high overall entropy ({overall:.2f} bits/byte), indicating packing, encryption, or compression",
            severity="MEDIUM",
            score_impact=25.0
        ))
    elif high_entropy_blocks > 0:
        findings.append(Finding(
            category="HIGH_BLOCK_ENTROPY",
            description=f"Detected {high_entropy_blocks} high-entropy 4KB block(s) (entropy >= {threshold}), indicative of embedded ciphertext or packed stagers",
            severity="LOW",
            score_impact=15.0
        ))

    return EntropyResult(
        overall_entropy=overall,
        block_size=block_size,
        total_blocks=total_blocks,
        high_entropy_blocks=high_entropy_blocks,
        is_packed_or_encrypted=is_packed,
        findings=findings
    )


# 5. Link & URL Inspection Engine
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")
PUNYCODE_REGEX = re.compile(r"xn--[a-zA-Z0-9\-]+", re.IGNORECASE)
SUSPICIOUS_PATH_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "update",
    "banking", "secure", "wallet", "recover", "billing", "confirm", "kyc"
}

def check_link(url: str) -> LinkScanResult:
    """
    Inspects URL for IP-literal hosts, shorteners, punycode/homographs,
    userinfo tricks, excessive subdomains, risky TLDs, and typosquatting.
    """
    findings: List[Finding] = []
    total_score = 0.0

    parsed = urlparse(url if "://" in url else f"http://{url}")
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    # 1. Userinfo trick: e.g. http://google.com@evil.com
    if "@" in netloc:
        findings.append(Finding(
            category="USERINFO_TRICK",
            description="URL uses '@' userinfo trick to mask true destination host",
            severity="HIGH",
            score_impact=50.0
        ))
        netloc = netloc.split("@")[-1]

    # Strip port if present
    hostname = netloc.split(":")[0]

    # 2. IP-Literal Host check
    if IPV4_REGEX.match(netloc) or hostname.startswith("["):
        findings.append(Finding(
            category="IP_LITERAL_HOST",
            description=f"URL points to a raw IP literal ({hostname}) rather than a registered domain name",
            severity="HIGH",
            score_impact=45.0
        ))

    # 3. Punycode / Homograph check
    if PUNYCODE_REGEX.search(hostname):
        findings.append(Finding(
            category="PUNYCODE_HOMOGRAPH",
            description=f"Punycode encoding detected in domain '{hostname}', possible homograph spoofing",
            severity="HIGH",
            score_impact=40.0
        ))

    # 4. Known URL Shorteners
    if hostname in URL_SHORTENERS:
        findings.append(Finding(
            category="URL_SHORTENER",
            description=f"URL uses shortening service '{hostname}' to obscure final destination",
            severity="MEDIUM",
            score_impact=25.0
        ))

    # 5. Risky Top-Level Domains (TLDs)
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in RISKY_TLDS:
        findings.append(Finding(
            category="RISKY_TLD",
            description=f"Domain registered under high-abuse TLD '.{tld}'",
            severity="MEDIUM",
            score_impact=30.0
        ))

    # 6. Excessive Subdomains (>= 4 dots in hostname)
    if hostname.count(".") >= 4:
        findings.append(Finding(
            category="EXCESSIVE_SUBDOMAINS",
            description=f"Excessive subdomain nesting ({hostname.count('.')} levels) commonly used in phishing kits",
            severity="LOW",
            score_impact=15.0
        ))

    # 7. Typosquatting / Brand Spoofing via Damerau-Levenshtein
    domain_labels = hostname.split(".")
    second_level = domain_labels[-2] if len(domain_labels) >= 2 else domain_labels[0]
    normalized_label = normalize_leetspeak(second_level)

    for brand in TARGET_BRANDS:
        # Check 1: Leetspeak visual substitution match (e.g. paypa1 -> paypal)
        if normalized_label == brand and second_level != brand:
            findings.append(Finding(
                category="TYPOSQUATTING",
                description=f"Domain '{second_level}' is a leetspeak visual typosquat spoofing brand '{brand}'",
                severity="HIGH",
                score_impact=55.0
            ))
            break

        # Check 2: Exact brand embedded inside longer label (e.g. paypal-security-update)
        if brand in second_level and second_level != brand:
            findings.append(Finding(
                category="BRAND_IMPERSONATION",
                description=f"Domain '{second_level}' embeds target brand '{brand}'",
                severity="HIGH",
                score_impact=50.0
            ))
            break

        # Check 3: Typosquat edit distance check (distance 1 or 2)
        dist = damerau_levenshtein_distance(normalized_label, brand)
        if 1 <= dist <= 2 and len(second_level) >= 4:
            findings.append(Finding(
                category="TYPOSQUATTING",
                description=f"Domain '{second_level}' is a typosquat variant of brand '{brand}' (distance: {dist})",
                severity="HIGH",
                score_impact=55.0
            ))
            break

    # 8. Suspicious Path & Query Keywords
    full_path_query = f"{path}?{query}"
    matched_kw = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in full_path_query]
    if matched_kw:
        findings.append(Finding(
            category="PHISHING_PATH_KEYWORD",
            description=f"Suspicious phishing path/query tokens detected: {', '.join(matched_kw[:3])}",
            severity="LOW",
            score_impact=min(25.0, len(matched_kw) * 10.0)
        ))

    for f in findings:
        total_score += f.score_impact

    clamped_score = min(100.0, round(total_score, 1))
    verdict, color = final_verdict(clamped_score)

    return LinkScanResult(
        url=url,
        score=clamped_score,
        verdict=verdict,
        verdict_color=color,
        hostname=hostname,
        findings=findings
    )


# 6. Message & SMS Lexicon / Fraud Scanner
LEXICON_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "URGENCY": {
        "keywords": [
            "urgent", "immediately", "within 24 hours", "suspended", "terminated",
            "blocked", "unauthorized", "act now", "action required", "expires today"
        ],
        "severity": "MEDIUM",
        "impact": 20.0,
        "desc": "High-urgency psychological coercion phrasing"
    },
    "OTP_KYC": {
        "keywords": [
            "otp", "one-time password", "verification code", "kyc", "pan card",
            "aadhaar", "bank account", "security pin", "do not share", "verify kyc"
        ],
        "severity": "HIGH",
        "impact": 35.0,
        "desc": "Sensitive authentication (OTP / KYC / PIN) credential harvesting"
    },
    "CREDENTIAL_SOLICITATION": {
        "keywords": [
            "enter password", "login here", "confirm credentials", "verify identity",
            "update card", "account locked", "verify now", "reset access"
        ],
        "severity": "HIGH",
        "impact": 30.0,
        "desc": "Direct credential solicitation triggers"
    },
    "PRIZE_BAIT": {
        "keywords": [
            "won", "lottery", "cash prize", "congratulations", "free gift",
            "winner", "claim now", "reward balance", "selected to receive"
        ],
        "severity": "MEDIUM",
        "impact": 25.0,
        "desc": "Lottery / Prize baiting social engineering"
    }
}

URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

def check_message(text: str) -> MessageScanResult:
    """
    Inspects message/SMS text for weighted social engineering lexicon,
    extracts embedded URLs, inspects them, and calculates an explainable score.
    """
    t_lower = text.lower()
    findings: List[Finding] = []
    total_score = 0.0

    # 1. Lexicon scanning
    for cat_name, cat_data in LEXICON_CATEGORIES.items():
        matched = [kw for kw in cat_data["keywords"] if kw in t_lower]
        if matched:
            finding = Finding(
                category=cat_name,
                description=f"{cat_data['desc']} (Matched: {', '.join(matched[:3])})",
                severity=cat_data["severity"],
                score_impact=cat_data["impact"]
            )
            findings.append(finding)
            total_score += cat_data["impact"]

    # 2. Extract and inspect URLs
    urls_found = URL_REGEX.findall(text)
    link_results: List[LinkScanResult] = []
    max_link_score = 0.0

    for u in urls_found:
        lr = check_link(u)
        link_results.append(lr)
        if lr.score > max_link_score:
            max_link_score = lr.score

    if urls_found:
        total_score += (max_link_score * 0.7)  # Heavily weight link danger
        if max_link_score >= 70.0:
            findings.append(Finding(
                category="MESSAGE_EMBEDDED_DANGEROUS_LINK",
                description=f"Message embeds confirmed dangerous destination link ({urls_found[0]})",
                severity="CRITICAL",
                score_impact=30.0
            ))
            total_score += 30.0

    clamped_score = min(100.0, round(total_score, 1))
    verdict, color = final_verdict(clamped_score)

    return MessageScanResult(
        message=text,
        score=clamped_score,
        verdict=verdict,
        verdict_color=color,
        urls_found=urls_found,
        link_results=link_results,
        findings=findings
    )


# 7. Offline Password Strength & Entropy Evaluator
COMMON_PASSWORDS: set[str] = {
    "password", "123456", "12345678", "123456789", "12345", "qwerty",
    "password123", "admin", "admin123", "welcome", "welcome1", "letmein",
    "football", "iloveyou", "master", "monkey", "sunshine", "princess",
    "pass1234", "root", "toor", "test", "test1234"
}

KEYBOARD_SEQUENCES: List[str] = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321", "abcdefghijklmnopqrstuvwxyz"
]

def check_password(pw: str) -> PasswordResult:
    """
    Offline password auditor assessing entropy bits, dictionary collisions,
    keyboard walking patterns, and character diversity.
    Outputs strength score 0-100 (where >=70 is SAFE, 30-69 SUSPICIOUS, <30 DANGEROUS).
    """
    findings: List[Finding] = []
    length = len(pw)

    if length == 0:
        return PasswordResult(
            password_masked="",
            score=0.0,
            verdict="DANGEROUS",
            verdict_color="red",
            entropy_bits=0.0,
            findings=[Finding("EMPTY_PASSWORD", "Password cannot be empty", "CRITICAL", 100.0)]
        )

    # Calculate Character Set Pool Size
    pool = 0
    has_lower = bool(re.search(r"[a-z]", pw))
    has_upper = bool(re.search(r"[A-Z]", pw))
    has_digit = bool(re.search(r"\d", pw))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", pw))

    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_special: pool += 33

    entropy_bits = round(length * math.log2(pool), 2) if pool > 0 else 0.0

    # 1. Check against known common passwords
    pw_lower = pw.lower()
    is_common = pw_lower in COMMON_PASSWORDS
    if is_common:
        findings.append(Finding(
            category="COMMON_PASSWORD_MATCH",
            description="Password appears in top public compromised password dictionaries",
            severity="CRITICAL",
            score_impact=70.0
        ))

    # 2. Keyboard walking pattern checks
    for seq in KEYBOARD_SEQUENCES:
        for i in range(len(seq) - 3):
            sub = seq[i:i + 4]
            if sub in pw_lower:
                findings.append(Finding(
                    category="KEYBOARD_WALK_PATTERN",
                    description=f"Predictable keyboard sequence detected ('{sub}')",
                    severity="HIGH",
                    score_impact=25.0
                ))
                break

    # 3. Repeated Characters (e.g. aaaaa, 11111)
    if re.search(r"(.)\1{3,}", pw):
        findings.append(Finding(
            category="REPEATED_CHARS",
            description="Contains 4 or more repeated identical characters",
            severity="MEDIUM",
            score_impact=20.0
        ))

    # 4. Length checks
    if length < 8:
        findings.append(Finding(
            category="INSUFFICIENT_LENGTH",
            description="Length is under minimum recommended standard (8 characters)",
            severity="HIGH",
            score_impact=30.0
        ))

    # Strength Score Calculation (0 weak/dangerous, 100 strong/safe)
    strength = 0.0
    if entropy_bits >= 60: strength += 40.0
    elif entropy_bits >= 45: strength += 25.0
    elif entropy_bits >= 30: strength += 15.0

    diversity_count = sum([has_lower, has_upper, has_digit, has_special])
    strength += (diversity_count * 10.0)

    if length >= 14: strength += 20.0
    elif length >= 10: strength += 10.0

    # Deductions
    for f in findings:
        strength -= f.score_impact

    strength_score = max(0.0, min(100.0, round(strength, 1)))

    # For password, HIGH strength = SAFE, LOW strength = DANGEROUS
    if strength_score >= 70.0:
        verdict, color = "SAFE", "emerald"
    elif strength_score >= 35.0:
        verdict, color = "SUSPICIOUS", "amber"
    else:
        verdict, color = "DANGEROUS", "red"

    masked = pw[0] + ("*" * (length - 2)) + pw[-1] if length >= 3 else "*" * length

    return PasswordResult(
        password_masked=masked,
        score=strength_score,
        verdict=verdict,
        verdict_color=color,
        entropy_bits=entropy_bits,
        findings=findings
    )

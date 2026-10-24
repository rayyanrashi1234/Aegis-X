import os
import json
import random
import time
import queue
from datetime import datetime
from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS
import google.generativeai as genai

# --- GEMINI AI MASTERMIND CONFIGURATION ---
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", "AQ.Ab8RN6J4Fc_bhGNFfEmB5YkjmUPIWWF-VKJqz8yQr5Vh8Xk-Vw"))

# FIX: Use 'gemini-1.5-flash-latest' to avoid 404 errors and ensure native PDF support.
model = genai.GenerativeModel('gemini-1.5-flash-latest')

app = Flask(__name__)
CORS(app)

sse_subscribers = []

def broadcast_event(entry):
    dead = []
    for q in sse_subscribers:
        try:
            q.put_nowait(entry)
        except Exception:
            dead.append(q)
    for q in dead:
        if q in sse_subscribers:
            sse_subscribers.remove(q)

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    return response

threat_log = []
sos_alerts = []
hp_captures = [] 
incidents = []   

# --- REAL GEMINI AI BRAIN ---
def ai_brain(content):
    if not content or len(content.strip()) == 0:
        return "SAFE", "ALLOW", "No payload provided", "", 100

    prompt = f"""
    You are Aegis-X, an elite AI Security Operations Center (SOC) Mastermind.
    Analyze the following network payload/telemetry and classify the threat accurately without false assumptions.
    
    Payload: "{content}"
    
    Respond ONLY with a valid, raw JSON object (no markdown, no code blocks) using this exact format:
    {{
        "tier": "SAFE" or "TIER_1" (Spam/Minor) or "TIER_2" (Exploit) or "TIER_3" (Critical APT/Ransomware),
        "action": "ALLOW" or "NULLIFY" or "POISON" or "SOS",
        "reason": "A strict, professional 1-sentence technical explanation of your decision",
        "poison": "If action is POISON, provide a fake counter-payload name (e.g. 'Fake_Creds_Tracker'). Otherwise leave empty.",
        "confidence": <integer from 0 to 100>
    }}
    """
    try:
        response = model.generate_content(prompt)
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        data = json.loads(clean_json)
        
        return (
            data.get("tier", "SAFE"),
            data.get("action", "ALLOW"),
            data.get("reason", "Analyzed by Gemini Mastermind"),
            data.get("poison", ""),
            data.get("confidence", 90)
        )
    except Exception as e:
        print(f"\n[!] Gemini API Error: {e}\n")
        return "TIER_1", "NULLIFY", "Fallback mode: Suspicious activity intercepted natively", "", 50

@app.route('/')
@app.route('/index')
@app.route('/index.html')
def serve_index():
    if os.path.exists('soc.html'):
        return send_file('soc.html')
    return "soc.html not found", 404

@app.route('/soc')
@app.route('/soc.html')
def serve_soc():
    if os.path.exists('soc.html'):
        return send_file('soc.html')
    return "soc.html not found", 404

@app.route('/android')
@app.route('/andriod')
def serve_android():
    if os.path.exists('andriod.html'):
        return send_file('andriod.html')
    return "andriod.html not found", 404

@app.route('/api/health')
def health_check():
    return jsonify({
        "status": "online",
        "service": "Aegis-X SOC Mastermind (Gemini Powered)",
        "active_sse_clients": len(sse_subscribers),
        "total_threats": len(threat_log),
        "sos_count": len(sos_alerts),
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.json or {}
    client_id = data.get('identifier') or data.get('client_id') or 'Android-CODZE-01'
    device_name = data.get('device_name') or 'Android Pixel'
    content = data.get('content', '')
    
    tier, action, reason, poison, confidence = ai_brain(content)
    source_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    
    entry = {
        "id": f"EVT-{int(time.time()*1000)}-{random.randint(100,999)}",
        "time": datetime.now().strftime("%H:%M:%S"),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tier": tier,
        "action": action,
        "reason": f"[{device_name}] {reason}",
        "poison": poison,
        "confidence": confidence,
        "source": client_id,
        "device_name": device_name,
        "source_ip": source_ip,
        "payload_preview": content[:120]
    }
    
    if action == "SOS" or tier == "TIER_3":
        sos_alerts.append(entry)
            
    threat_log.append(entry)
    broadcast_event(entry)
    
    return jsonify({
        "tier": tier,
        "action": action,
        "reason": reason,
        "poison_payload": poison,
        "confidence": confidence,
        "event_id": entry["id"]
    })

@app.route('/api/telemetry', methods=['GET'])
def get_telemetry():
    blocked = sum(1 for l in threat_log if l.get('tier') not in ('SAFE', None))
    poisoned = sum(1 for l in threat_log if l.get('poison'))
    return jsonify({
        "status": "online",
        "timestamp": datetime.now().isoformat(),
        "stats": {
            "total": len(threat_log),
            "blocked": blocked,
            "poisoned": poisoned,
            "honeypot": len(hp_captures),
            "incidents": len(incidents),
            "sos": len(sos_alerts)
        },
        "recent_logs": threat_log[-50:],
        "honeypot_captures": hp_captures[-25:],
        "incident_reports": incidents[-25:],
        "sos_alerts": sos_alerts[-10:]
    })

@app.route('/api/v1/telemetry/stream')
def telemetry_stream():
    def event_stream():
        client_queue = queue.Queue(maxsize=100)
        sse_subscribers.append(client_queue)
        yield f": connected {int(time.time())}\n\n"
        try:
            while True:
                try:
                    entry = client_queue.get(timeout=10)
                    yield f"data: {json.dumps(entry)}\n\n"
                except queue.Empty:
                    yield f": keepalive {int(time.time())}\n\n"
        except GeneratorExit:
            if client_queue in sse_subscribers:
                sse_subscribers.remove(client_queue)

    return Response(event_stream(), mimetype="text/event-stream", headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
        'Access-Control-Allow-Origin': '*'
    })

@app.route('/api/v1/submit_payload', methods=['POST'])
def submit_payload():
    data = request.json or {}
    return jsonify({
        "status": "success",
        "message": "Payload executed",
        "privileges": "uid=0(root) gid=0(root)",
        "canary_token": "FAKE-TOKEN-999"
    })

# --- GEMINI AI FILE DOCUMENT ANALYZER (NATIVE PDF SUPPORT) ---
@app.route('/api/v1/analyze_file', methods=['POST'])
def analyze_file():
    data = request.json or {}
    filename = data.get('filename', 'unknown_file')
    content = data.get('content', '')
    
    if not content:
        return jsonify({"status": "ERROR", "error": "No file content provided"}), 400
        
    prompt = f"""
    You are a cybersecurity malware analyzer. Analyze the following uploaded document/file for malicious intent (malware, exploits, phishing, ransomware, etc.).
    File name: {filename}
    
    Return a raw JSON response strictly in this format (no markdown formatting):
    {{
        "status": "SUCCESS",
        "is_malicious": true or false,
        "incident_report": {{
            "severity": "CRITICAL", "HIGH", "MEDIUM", "LOW", or "CLEAN",
            "short_summary": "A 1-sentence summary of the threat",
            "detailed_analysis": "A detailed 3-4 sentence explanation of exactly what the file does, what techniques it uses, and why it is a threat (or why it is safe)."
        }},
        "file_metadata": {{"sha256_short": "generate_fake_hash_here"}},
        "geo_profile": {{"country_code": "XX", "attributed_actor": "Unknown"}}
    }}
    """
    try:
        # Handle Base64 Data URL (e.g., from FileReader.readAsDataURL) for native PDF/Image support
        if content.startswith('data:'):
            header, encoded_data = content.split(',', 1)
            mime_type = header.split(':')[1].split(';')[0]
            
            response = model.generate_content([
                prompt,
                {
                    "inline_data": {
                        "mime_type": mime_type,
                        "data": encoded_data
                    }
                }
            ])
        else:
            # Fallback for plain text content
            response = model.generate_content(prompt + f"\n\nFile Content Preview:\n{content[:5000]}")
            
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        result = json.loads(clean_json)
        
        if result.get("is_malicious"):
            entry = {
                "id": f"EVT-{int(time.time()*1000)}-{random.randint(100,999)}",
                "time": datetime.now().strftime("%H:%M:%S"),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tier": "TIER_3" if result.get("incident_report", {}).get("severity") in ["CRITICAL", "HIGH"] else "TIER_2",
                "action": "SOS",
                "reason": f"[File Upload] {result.get('incident_report', {}).get('short_summary', 'Malicious file detected')}",
                "poison": "",
                "confidence": 95,
                "source": "Android-Client-Upload",
                "device_name": "Android Pixel",
                "source_ip": request.headers.get('X-Forwarded-For', '127.0.0.1'),
                "payload_preview": filename
            }
            threat_log.append(entry)
            broadcast_event(entry)
            
        return jsonify(result)
    except Exception as e:
        print(f"\n[!] Gemini API File Analyzer Error: {e}\n")
        return jsonify({"status": "ERROR", "error": str(e)}), 500

# --- GEMINI AI WEB URL / BROWSER SAFETY ANALYZER ---
@app.route('/api/v1/analyze_url', methods=['POST'])
def analyze_url():
    data = request.json or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"status": "ERROR", "error": "No URL provided"}), 400
        
    prompt = f"""
    You are an advanced Web Security and Threat Intelligence AI. Analyze the following URL or website domain for safety risks, including phishing, malware distribution, spam, credential harvesting, or scam indicators.
    URL/Domain: {url}
    
    CRITICAL RULE: Major, well-known legitimate domains (e.g., youtube.com, google.com, github.com, amazon.com, microsoft.com, wikipedia.org) MUST be classified as "SAFE" with a risk score between 0 and 5, unless the URL contains obvious malicious subdomains or deceptive paths (e.g., youtube.com-verify-login.net). Do not flag legitimate mainstream websites as spam or phishing.
    
    Return a raw JSON response strictly in this format (no markdown formatting):
    {{
        "status": "SUCCESS",
        "url": "{url}",
        "safety_status": "SAFE" or "SPAM" or "PHISHING" or "MALICIOUS",
        "risk_score": <integer from 0 (completely safe) to 100 (extreme danger)>,
        "summary": "A 1-sentence concise verdict on whether this site is safe or dangerous.",
        "detailed_analysis": "A detailed 2-3 sentence explanation of potential threats, domain characteristics, or safety guarantees associated with this URL."
    }}
    """
    try:
        response = model.generate_content(prompt)
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        result = json.loads(clean_json)
        
        if result.get("safety_status") in ["SPAM", "PHISHING", "MALICIOUS"]:
            entry = {
                "id": f"EVT-{int(time.time()*1000)}-{random.randint(100,999)}",
                "time": datetime.now().strftime("%H:%M:%S"),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tier": "TIER_3" if result.get("risk_score", 0) > 75 else "TIER_2",
                "action": "BLOCK",
                "reason": f"[Browser Security] {result.get('summary', 'Unsafe URL intercepted')}",
                "poison": "",
                "confidence": result.get("risk_score", 90),
                "source": "Android-Browser-Shield",
                "device_name": "Android Pixel",
                "source_ip": request.headers.get('X-Forwarded-For', '127.0.0.1'),
                "payload_preview": url
            }
            threat_log.append(entry)
            broadcast_event(entry)
            
        return jsonify(result)
    except Exception as e:
        print(f"\n[!] Gemini URL Analyzer Error: {e}\n")
        return jsonify({"status": "ERROR", "error": str(e)}), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  [AEGIS-X] GEMINI AI MASTERMIND ONLINE (STANDALONE)")
    print("="*60)
    print("  Dashboard: http://localhost:5000/soc")
    print("  Client:    http://localhost:5000/android\n")
    app.run(host='0.0.0.0', port=5000, debug=True)
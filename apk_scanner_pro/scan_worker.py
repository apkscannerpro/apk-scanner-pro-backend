import requests
import os
import time
import json
import hashlib
from openai import OpenAI
from datetime import datetime

# --- VirusTotal API ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# --- Bitdefender Affiliate (no API, just link) ---
BITDEFENDER_AFFILIATE_LINK = (
    "https://www.bitdefender.com/site/view/trial.html?affid=12345"
)  # replace with your affiliate link

# --- AI Layer ---
AI_ENABLED = True
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


def _ai_assistant_summary(report_text: str):
    """Generate AI-powered summary of risks."""
    if not client:
        return {"Risk Assessment": "⚠️ AI not configured. Defaulting to VirusTotal verdicts."}
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": f"""
Analyze the following APK/URL scan results and summarize risk level
(Safe / Suspicious / Malicious). Be concise and user-friendly.

Report:
{report_text}
""",
                }
            ],
            max_tokens=150,
        )
        return {"Risk Assessment": resp.choices[0].message.content.strip()}
    except Exception:
        return {"Risk Assessment": "⚠️ AI summary unavailable. Defaulting to VirusTotal verdicts."}


def _normalize_results(vt_engines, vt_stats, ai_summary=None, note=None):
    """Unify scan results into branded SaaS-ready format."""
    result = {
        "status": "success",
        "powered_by": "APK Scanner Pro",
        "verdict": "Safe",
        "virustotal": vt_engines or {},
        "bitdefender": {
            "Affiliate Offer": f"Protect your device with Bitdefender 👉 {BITDEFENDER_AFFILIATE_LINK}"
        },
        "ai": ai_summary or {},
    }

    if vt_stats.get("malicious", 0) > 0:
        result["verdict"] = "Malicious"
    elif vt_stats.get("suspicious", 0) > 0:
        result["verdict"] = "Suspicious"

    if note:
        result["note"] = note
    return result


def _poll_analysis(analysis_id):
    """Poll VirusTotal until analysis is complete or timeout."""
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(18):  # ~90s max
        resp = requests.get(analysis_url, headers=VT_HEADERS)
        if resp.status_code != 200:
            return {"status": "error", "message": f"Analysis request failed: {resp.status_code}"}
        data = resp.json()
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return data
        time.sleep(5)
    return {"status": "error", "message": "Timed out waiting for VirusTotal results"}


def _fetch_existing_file_report(file_hash):
    """Fetch existing report if VT returns 409 for duplicate file."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    resp = requests.get(url, headers=VT_HEADERS)
    if resp.status_code == 200:
        data = resp.json()
        vt_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_engines = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}
        return _normalize_results(vt_engines, vt_stats, ai_summary, note="Fetched from existing VT report")
    return {"status": "error", "message": f"Failed to fetch existing report: {resp.status_code}"}


def _sha256_file(file_path):
    """Calculate SHA256 hash of a file (for VT duplicate fetch)."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def scan_apk_file(file_path, premium=False, payment_ref=None):
    """Scan an uploaded APK file with VirusTotal + AI layer."""
    try:
        if not VIRUSTOTAL_API_KEY:
            return {"status": "error", "message": "VirusTotal API key missing."}

        # --- Premium enforcement ---
        if premium and not payment_ref:
            return {"status": "error", "message": "❌ Premium scans require a valid payment reference."}

        # --- Free / Basic-paid enforcement (ENV-controlled) ---
        scans_file = os.path.join(os.path.dirname(__file__), "scans.json")
        scans_data = {}
        if os.path.exists(scans_file):
            try:
                with open(scans_file, "r") as f:
                    scans_data = json.load(f)
            except Exception:
                scans_data = {}

        today = datetime.utcnow().strftime("%Y-%m-%d")
        free_scans_today = scans_data.get(today, 0)
        FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", 50))  # <- ENV-controlled

        if not premium:
            if free_scans_today >= FREE_LIMIT:
                # require $1 basic-paid
                if not payment_ref:
                    return {"status": "error", "message": "Free scan limit reached. Please pay $1 to continue."}
            else:
                scans_data[today] = free_scans_today + 1
                # Thread-safe write
                lock = threading.Lock()
                with lock:
                    with open(scans_file, "w") as f:
                        json.dump(scans_data, f)

        # --- Upload to VirusTotal ---
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            resp = requests.post(VT_SCAN_URL, headers=VT_HEADERS, files=files)

        if resp.status_code == 409:
            # Duplicate file — fetch existing report by actual SHA256
            file_hash = _sha256_file(file_path)
            return _fetch_existing_file_report(file_hash)

        if resp.status_code not in (200, 202):
            return {
                "status": "error",
                "message": f"VT file submission failed: {resp.status_code}",
                "details": resp.text,
            }

        vt_data = resp.json()
        analysis_id = vt_data.get("data", {}).get("id")
        if not analysis_id:
            return {"status": "error", "message": "No VT file analysis ID", "raw": vt_data}

        # --- Poll until ready ---
        vt_analysis = _poll_analysis(analysis_id)
        if "status" in vt_analysis and vt_analysis["status"] == "error":
            return vt_analysis

        vt_stats = vt_analysis.get("data", {}).get("attributes", {}).get("stats", {}) or {}
        vt_engines = vt_analysis.get("data", {}).get("attributes", {}).get("results", {}) or {}
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}

        return _normalize_results(vt_engines, vt_stats, ai_summary)

    except Exception as e:
        print(f"[ERROR] scan_apk_file failed for {file_path}: {e}")
        return {"status": "error", "message": f"Exception in scan_apk_file: {str(e)}"}



def scan_url(target_url, premium=False, payment_ref=None):
    """Scan Play Store link or any URL via VirusTotal + AI, enforce free/basic-paid/premium quota."""
    try:
        if not VIRUSTOTAL_API_KEY:
            return {"status": "error", "message": "VirusTotal API key missing."}

        # --- Premium enforcement ---
        if premium and not payment_ref:
            return {"status": "error", "message": "❌ Premium scans require a valid payment reference."}

        if "play.google.com/store/apps/details?id=" not in target_url:
            return {"status": "error", "message": "Only valid Play Store URLs are allowed."}

        # --- Free / Basic-paid enforcement ---
        scans_file = os.path.join(os.path.dirname(__file__), "scans.json")
        scans_data = {}
        if os.path.exists(scans_file):
            try:
                with open(scans_file, "r") as f:
                    scans_data = json.load(f)
            except Exception:
                scans_data = {}

        today = datetime.utcnow().strftime("%Y-%m-%d")
        free_scans_today = scans_data.get(today, 0)
        FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", 50))  # <- ENV controlled

        if not premium:
            if free_scans_today >= FREE_LIMIT:
                # require $1 basic-paid
                if not payment_ref:
                    return {"status": "error", "message": "Free scan limit reached. Please pay $1 to continue."}
            else:
                scans_data[today] = free_scans_today + 1
                # Thread-safe write
                lock = threading.Lock()
                with lock:
                    with open(scans_file, "w") as f:
                        json.dump(scans_data, f)

        # --- Submit URL to VirusTotal ---
        url_resp = requests.post(VT_URL_SCAN, headers=VT_HEADERS, data={"url": target_url})
        if url_resp.status_code not in (200, 202):
            return {"status": "error", "message": f"VT URL submission failed: {url_resp.status_code}", "details": url_resp.text}

        vt_data = url_resp.json()
        analysis_id = vt_data.get("data", {}).get("id")
        if not analysis_id:
            return {"status": "error", "message": "No VT URL analysis ID", "raw": vt_data}

        vt_analysis = _poll_analysis(analysis_id)
        if "status" in vt_analysis and vt_analysis["status"] == "error":
            return vt_analysis

        vt_stats = vt_analysis.get("data", {}).get("attributes", {}).get("stats", {}) or {}
        vt_engines = vt_analysis.get("data", {}).get("attributes", {}).get("results", {}) or {}
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}
        return _normalize_results(vt_engines, vt_stats, ai_summary)

    except Exception as e:
        print(f"[ERROR] scan_url failed for {target_url}: {e}")
        return {"status": "error", "message": f"Exception in scan_url: {str(e)}"}



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
    """
    Poll VirusTotal until analysis is complete or timeout (~5 minutes).
    Retries up to 60 times with 5s interval for larger APKs.
    Always returns a dict safe for _finalize_scan.
    """
    import time, requests

    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    print(f"[DEBUG] Polling VT analysis: {analysis_id}")

    for attempt in range(1, 61):  # 60 attempts, 5s interval (~5min)
        try:
            resp = requests.get(analysis_url, headers=VT_HEADERS)
        except Exception as e:
            print(f"[ERROR] VT request exception on attempt {attempt}: {e}")
            time.sleep(5)
            continue

        if resp.status_code != 200:
            print(f"[ERROR] VT request failed on attempt {attempt}: {resp.status_code}, {resp.text}")
            time.sleep(5)
            continue

        data = resp.json()
        if not data or "data" not in data:
            print(f"[WARN] VT response missing 'data' on attempt {attempt}: {data}")
            time.sleep(5)
            continue

        status = data.get("data", {}).get("attributes", {}).get("status")
        print(f"[DEBUG] Attempt {attempt}: VT analysis status = {status}")

        if status == "completed":
            print(f"[DEBUG] VT analysis completed: {analysis_id}")
            return data

        if status == "queued":
            print(f"[DEBUG] VT analysis still queued, waiting... attempt {attempt}")

        time.sleep(5)

    print(f"[ERROR] VT analysis timed out after 60 attempts (~5min): {analysis_id}")
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


def _scan_job_file(user_email=None, tmp_path=None, file_name_or_url=None, premium=False, payment_ref=None, basic_paid=False):
    """
    Handles scanning an uploaded APK file.
    - Safe for VirusTotal API failures
    - Always returns a dict compatible with _finalize_scan
    - Auto-sends email report
    - Cleans up temp files
    """
    scan_result = {"verdict": "Unknown", "virustotal": {}}

    try:
        print(f"[DEBUG] Starting file scan for {file_name_or_url}, premium={premium}, basic_paid={basic_paid}")
        scan_result = scan_apk_file(tmp_path, premium=premium, payment_ref=payment_ref)
        print(f"[DEBUG] Scan result received: {scan_result}")

    except Exception as e:
        print(f"[ERROR] Exception during scan_apk_file for {file_name_or_url}: {e}")
        scan_result = {"verdict": "Unknown", "virustotal": {}, "note": f"Scan exception: {str(e)}"}

    finally:
        # Ensure temp file is removed
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
                print(f"[DEBUG] Temporary file removed: {tmp_path}")
        except Exception as e:
            print(f"[ERROR] Failed to remove temp file: {e}")

    # Finalize scan and send email safely
    try:
        return _finalize_scan(
            scan_result,
            user_email,
            file_name_or_url=file_name_or_url,
            premium=premium,
            payment_ref=payment_ref,
            basic_paid=basic_paid
        )
    except Exception as e:
        print(f"[ERROR] Exception in _finalize_scan for {file_name_or_url}: {e}")
        # Fallback dict to ensure safe return
        return {"success": False, "email": user_email, "premium": premium, "basic_paid": basic_paid, "note": f"_finalize_scan failed: {str(e)}"}



def scan_apk_file(file_path, premium=False, payment_ref=None):
    """
    Scan an uploaded APK file via VirusTotal API + optional AI summary.
    Returns a dict always safe for _finalize_scan.
    """
    import os, json, requests

    try:
        if not VIRUSTOTAL_API_KEY:
            return {"status": "error", "message": "VirusTotal API key missing."}

        # --- Upload file to VirusTotal ---
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            print(f"[DEBUG] Uploading APK to VT: {file_path}")
            resp = requests.post(VT_SCAN_URL, headers=VT_HEADERS, files=files)

        # Handle duplicate file
        if resp.status_code == 409:
            file_hash = _sha256_file(file_path)
            print(f"[DEBUG] Duplicate file detected, fetching existing report: {file_hash}")
            return _fetch_existing_file_report(file_hash)

        if resp.status_code not in (200, 202):
            print(f"[ERROR] VT file submission failed: {resp.status_code} {resp.text}")
            return {"status": "error", "message": f"VT file submission failed: {resp.status_code}", "details": resp.text}

        vt_data = resp.json()
        analysis_id = vt_data.get("data", {}).get("id")
        if not analysis_id:
            print(f"[ERROR] No analysis ID returned from VT: {vt_data}")
            return {"status": "error", "message": "No VT file analysis ID", "raw": vt_data}

        # --- Poll VT until analysis completes ---
        vt_analysis = _poll_analysis(analysis_id)
        if "status" in vt_analysis and vt_analysis["status"] == "error":
            return {"status": "error", "message": vt_analysis.get("message", "VT analysis failed")}

        # --- Extract results ---
        vt_stats = vt_analysis.get("data", {}).get("attributes", {}).get("stats", {}) or {}
        vt_engines = vt_analysis.get("data", {}).get("attributes", {}).get("results", {}) or {}
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}

        return _normalize_results(vt_engines, vt_stats, ai_summary)

    except Exception as e:
        print(f"[ERROR] Exception in scan_apk_file: {e}")
        return {"status": "error", "message": f"Exception in scan_apk_file: {str(e)}"}



def scan_url(target_url, premium=False, payment_ref=None):
    """
    Scan Play Store URL via VirusTotal API + optional AI summary.
    Always returns a dict safe for _finalize_scan.
    """
    import os, json, requests

    try:
        if not VIRUSTOTAL_API_KEY:
            return {"status": "error", "message": "VirusTotal API key missing."}

        # Only allow Play Store URLs
        if "play.google.com/store/apps/details?id=" not in target_url:
            return {"status": "error", "message": "Only valid Play Store URLs are allowed."}

        print(f"[DEBUG] Submitting URL to VT: {target_url}")
        resp = requests.post(VT_URL_SCAN, headers=VT_HEADERS, data={"url": target_url})

        if resp.status_code not in (200, 202):
            print(f"[ERROR] VT URL submission failed: {resp.status_code} {resp.text}")
            return {"status": "error", "message": f"VT URL submission failed: {resp.status_code}", "details": resp.text}

        vt_data = resp.json()
        analysis_id = vt_data.get("data", {}).get("id")
        if not analysis_id:
            print(f"[ERROR] No analysis ID returned from VT URL submission: {vt_data}")
            return {"status": "error", "message": "No VT URL analysis ID", "raw": vt_data}

        # --- Poll VT until analysis completes ---
        vt_analysis = _poll_analysis(analysis_id)
        if "status" in vt_analysis and vt_analysis["status"] == "error":
            return {"status": "error", "message": vt_analysis.get("message", "VT URL analysis failed")}

        # --- Extract results ---
        vt_stats = vt_analysis.get("data", {}).get("attributes", {}).get("stats", {}) or {}
        vt_engines = vt_analysis.get("data", {}).get("attributes", {}).get("results", {}) or {}
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}

        return _normalize_results(vt_engines, vt_stats, ai_summary)

    except Exception as e:
        print(f"[ERROR] Exception in scan_url: {e}")
        return {"status": "error", "message": f"Exception in scan_url: {str(e)}"}




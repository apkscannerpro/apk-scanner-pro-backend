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

# --- Utility to poll VirusTotal results ---
def poll_virustotal_analysis(analysis_url, retries=10, delay=10):
    """Poll VirusTotal for analysis completion."""
    for i in range(retries):
        try:
            resp = requests.get(analysis_url, headers=VT_HEADERS)
            data = resp.json()
            status = data.get("data", {}).get("attributes", {}).get("status", "")
            if status == "completed":
                return data
            print(f"[DEBUG] Poll {i+1}/{retries}: status={status}")
        except Exception as e:
            print(f"[WARN] Polling VT failed: {e}")
        time.sleep(delay)
    print("[ERROR] VT polling timed out")
    return {"error": "Timeout waiting for VirusTotal analysis"}


# --- Bitdefender Affiliate (no API, just link) ---
BITDEFENDER_AFFILIATE_LINK = (
    "https://www.bitdefender.com/"
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
    """Unify scan results into branded SaaS-ready format (stable shape)."""
    try:
        # Compose canonical result
        result = {
            "status": "success",                       # legacy field
            "success": True,                           # canonical boolean used across code
            "powered_by": "APK Scanner Pro",
            "verdict": "Safe",
            "stats": vt_stats or {}, # ✅ show quick numbers: harmless/malicious/suspicious
            "virustotal": vt_engines or {}, # ✅ all engine details
            "affiliate": {
                "Bitdefender": f"Protect your device with Bitdefender 👉 {BITDEFENDER_AFFILIATE_LINK}"
            },
            "ai": ai_summary or {},
            "message": ""
        }

        # Verdict logic (prefer counts from vt_stats)
        malicious_count = int(vt_stats.get("malicious", 0) or 0)
        suspicious_count = int(vt_stats.get("suspicious", 0) or 0)

        if malicious_count > 0:
            result["verdict"] = "Malicious"
            result["message"] = f"{malicious_count} engines flagged as malicious."
        elif suspicious_count > 0:
            result["verdict"] = "Suspicious"
            result["message"] = f"{suspicious_count} engines flagged as suspicious."
        else:
            result["verdict"] = "Clean"
            result["message"] = "No malicious engines detected."

        if note:
            result["note"] = note

        return result

    except Exception as e:
        print(f"[ERROR] Exception in _normalize_results: {e}")
        return {
            "status": "error",
            "success": False,
            "verdict": "Unknown",
            "message": f"Normalization failed: {str(e)}",
            "stats": {},
            "virustotal": {}
        }



def _poll_analysis(analysis_id):
    """
    Poll VirusTotal until analysis is complete or timeout (~5 minutes).
    Always returns a normalized dict with keys:
      - success (bool)
      - verdict (str)
      - message (str)
      - stats (dict)
      - virustotal (dict)
    """
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    print(f"[DEBUG] Polling VT analysis: {analysis_id}")

    for attempt in range(1, 61):  # 60 attempts → ~5 min max
        try:
            resp = requests.get(analysis_url, headers=VT_HEADERS, timeout=15)
        except Exception as e:
            print(f"[ERROR] VT request exception (attempt {attempt}): {e}")
            time.sleep(5)
            continue

        if resp.status_code != 200:
            print(f"[ERROR] VT request failed (attempt {attempt}): {resp.status_code}, {resp.text}")
            time.sleep(5)
            continue

        try:
            data = resp.json()
        except Exception as e:
            print(f"[ERROR] Failed to parse VT JSON (attempt {attempt}): {e}")
            time.sleep(5)
            continue

        attrs = data.get("data", {}).get("attributes", {}) or {}
        status = attrs.get("status", "unknown")
        stats = attrs.get("stats", {}) or {}
        results = attrs.get("results", {}) or {}

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)

        print(f"[DEBUG] Attempt {attempt}: VT status = {status} (malicious={malicious}, suspicious={suspicious})")

        # Completed -> return canonical shape
        if status == "completed":
            verdict = "Malicious" if malicious > 0 else ("Suspicious" if suspicious > 0 else "Clean")
            return {
                "success": True,
                "verdict": verdict,
                "message": f"Completed with {malicious} malicious, {suspicious} suspicious detections",
                "stats": stats,
                "virustotal": results
            }

        # Still processing — wait and retry
        if status in ("queued", "in-progress", "running", None):
            time.sleep(5)
            continue

        # Unknown status but attributes exist -> return what we have
        if attrs:
            return {
                "success": True,
                "verdict": "Unknown",
                "message": f"Unexpected status '{status}' — partial data returned",
                "stats": stats,
                "virustotal": results
            }

    # Timed out
    print(f"[ERROR] VT analysis timed out after 60 attempts (~5min): {analysis_id}")
    return {
        "success": False,
        "verdict": "Timeout",
        "message": "Timed out waiting for VT results",
        "stats": {},
        "virustotal": {}
    }


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
    try:
        scan_result = {}
        try:
            scan_result = scan_apk_file(tmp_path, premium=premium, payment_ref=payment_ref)
            print(f"[DEBUG] File scan raw result for {file_name_or_url}: {scan_result}")
        except Exception as e:
            print(f"[ERROR] scan_apk_file failed for {file_name_or_url}: {e}")
            scan_result = {"status": "error", "message": f"scan_apk_file exception: {str(e)}"}

        if not scan_result or not isinstance(scan_result, dict):
            scan_result = {"verdict": "Unknown", "virustotal": {}}

        return _finalize_scan(
            scan_result,
            user_email,
            file_name_or_url=file_name_or_url,
            premium=premium,
            payment_ref=payment_ref,
            basic_paid=basic_paid
        )
    finally:
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
                print(f"[DEBUG] Temp file deleted: {tmp_path}")
            elif tmp_path:
                print(f"[WARN] Temp file not found for deletion: {tmp_path}")
        except Exception as e:
            print(f"[WARN] Failed to delete tmp file {tmp_path}: {e}")


def _scan_job_url(user_email=None, url_param=None, file_name_or_url=None, premium=False, payment_ref=None, basic_paid=False):
    scan_result = {}
    try:
        if is_direct_apk_url(url_param):
            local = download_apk_to_tmp(url_param)
            try:
                scan_result = scan_apk_file(local, premium=premium, payment_ref=payment_ref)
                print(f"[DEBUG] URL file scan result for {file_name_or_url or url_param}: {scan_result}")
            finally:
                try:
                    if os.path.exists(local):
                        os.remove(local)
                        print(f"[DEBUG] Temp file deleted: {local}")
                    else:
                        print(f"[WARN] Temp file not found for deletion: {local}")
                except Exception as e:
                    print(f"[WARN] Failed to delete tmp file {local}: {e}")
        else:
            try:
                scan_result = scan_url(url_param, premium=premium, payment_ref=payment_ref)
                print(f"[DEBUG] URL scan result for {file_name_or_url or url_param}: {scan_result}")
            except Exception as e:
                print(f"[ERROR] scan_url failed for {url_param}: {e}")
                scan_result = {"status": "error", "message": f"scan_url exception: {str(e)}"}

        if not scan_result or not isinstance(scan_result, dict):
            scan_result = {"verdict": "Unknown", "virustotal": {}}

        return _finalize_scan(
            scan_result,
            user_email,
            file_name_or_url=file_name_or_url or url_param,
            premium=premium,
            payment_ref=payment_ref,
            basic_paid=basic_paid
        )
    except Exception as e:
        print(f"[ERROR] _scan_job_url failed totally for {url_param}: {e}")
        return {"verdict": "Unknown", "virustotal": {}}


def scan_apk_file(file_path, premium=False, payment_ref=None):
    """
    Scan an uploaded APK file via VirusTotal API + optional AI summary.
    Always returns a normalized dict safe for _finalize_scan.
    """
    import os, json, requests

    try:
        if not VIRUSTOTAL_API_KEY:
            return {
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": "VirusTotal API key missing.",
                "virustotal": {},
                "stats": {}
            }

        # --- Upload file to VirusTotal ---
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            print(f"[DEBUG] Uploading APK to VT: {file_path}")
            resp = requests.post(VT_SCAN_URL, headers=VT_HEADERS, files=files, timeout=60)

        # Handle duplicate file
        if resp.status_code == 409:
            file_hash = _sha256_file(file_path)
            print(f"[DEBUG] Duplicate file detected, fetching existing report: {file_hash}")
            return _fetch_existing_file_report(file_hash)

        if resp.status_code not in (200, 202):
            print(f"[ERROR] VT file submission failed: {resp.status_code} {resp.text}")
            return {
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": f"VT file submission failed: {resp.status_code}",
                "virustotal": {},
                "stats": {},
                "details": resp.text
            }

        vt_data = resp.json()
        analysis_id = vt_data.get("data", {}).get("id")
        if not analysis_id:
            print(f"[ERROR] No analysis ID returned from VT: {vt_data}")
            return {
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": "No VT file analysis ID",
                "virustotal": {},
                "stats": {},
                "raw": vt_data
            }

        # --- Poll VT until analysis completes ---
        vt_analysis = _poll_analysis(analysis_id)
        if not vt_analysis.get("success", False):
            # poll failed or timed out
            return {
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": vt_analysis.get("message", "VT analysis failed"),
                "virustotal": vt_analysis.get("virustotal", {}),
                "stats": vt_analysis.get("stats", {})
            }

        # --- Extract results and normalize for caller ---
        vt_stats = vt_analysis.get("stats", {}) or {}
        vt_engines = vt_analysis.get("virustotal", {}) or {}
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}

        return _normalize_results(vt_engines, vt_stats, ai_summary)

    except Exception as e:
        print(f"[ERROR] Exception in scan_apk_file: {e}")
        return {
            "status": "error",
            "success": False,
            "verdict": "Unknown",
            "message": f"Exception in scan_apk_file: {str(e)}",
            "virustotal": {},
            "stats": {}
        }


def scan_url(target_url, premium=False, payment_ref=None):
    """
    Scan Play Store URL via VirusTotal API + optional AI summary.
    Always returns a normalized dict safe for _finalize_scan.
    """
    import os, json, requests

    try:
        if not VIRUSTOTAL_API_KEY:
            return {
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": "VirusTotal API key missing.",
                "virustotal": {},
                "stats": {}
            }

        # Only allow Play Store URLs
        if "play.google.com/store/apps/details?id=" not in target_url:
            return {
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": "Only valid Play Store URLs are allowed.",
                "virustotal": {},
                "stats": {}
            }

        print(f"[DEBUG] Submitting URL to VT: {target_url}")
        resp = requests.post(VT_URL_SCAN, headers=VT_HEADERS, data={"url": target_url}, timeout=30)

        if resp.status_code not in (200, 202):
            print(f"[ERROR] VT URL submission failed: {resp.status_code} {resp.text}")
            return {
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": f"VT URL submission failed: {resp.status_code}",
                "virustotal": {},
                "stats": {},
                "details": resp.text
            }

        vt_data = resp.json()
        analysis_id = vt_data.get("data", {}).get("id")
        if not analysis_id:
            print(f"[ERROR] No analysis ID returned from VT URL submission: {vt_data}")
            return {
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": "No VT URL analysis ID",
                "virustotal": {},
                "stats": {},
                "raw": vt_data
            }

        # --- Poll VT until analysis completes ---
        vt_analysis = _poll_analysis(analysis_id)
        if not vt_analysis.get("success", False):
            return {
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": vt_analysis.get("message", "VT URL analysis failed"),
                "virustotal": vt_analysis.get("virustotal", {}),
                "stats": vt_analysis.get("stats", {})
            }

        vt_stats = vt_analysis.get("stats", {}) or {}
        vt_engines = vt_analysis.get("virustotal", {}) or {}
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}

        return _normalize_results(vt_engines, vt_stats, ai_summary)

    except Exception as e:
        print(f"[ERROR] Exception in scan_url: {e}")
        return {
            "status": "error",
            "success": False,
            "verdict": "Unknown",
            "message": f"Exception in scan_url: {str(e)}",
            "virustotal": {},
            "stats": {}
        }






import requests
import os
import time
import json
from openai import OpenAI

# --- VirusTotal API ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# --- Bitdefender Affiliate (no API, just link) ---
BITDEFENDER_AFFILIATE_LINK = (
    "https://www.bitdefender.com/site/view/trial.html?affid=12345"
)  # replace with real affiliate link

# --- AI Layer ---
AI_ENABLED = True
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


def _ai_assistant_summary(report_text: str):
    if not client:
        return {"ai_summary": "⚠️ AI not configured. Using raw VT verdicts."}

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
        return {"ai_summary": resp.choices[0].message.content.strip()}
    except Exception as e:
        return {"ai_summary": f"AI summary failed: {str(e)}"}


def _normalize_results(vt_stats, ai_summary=None, note=None):
    result = {
        "verdict": "Safe",
        "virustotal": vt_stats or {},
        "ai": ai_summary or {},
        "affiliate_offer": f"Protect your device with Bitdefender 👉 {BITDEFENDER_AFFILIATE_LINK}",
    }
    if vt_stats.get("malicious", 0) > 0:
        result["verdict"] = "Malicious"
    elif vt_stats.get("suspicious", 0) > 0:
        result["verdict"] = "Suspicious"

    if note:
        result["note"] = note
    return result


def _poll_analysis(analysis_id):
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(18):  # ~90s max
        resp = requests.get(analysis_url, headers=VT_HEADERS)
        if resp.status_code != 200:
            return {"error": f"Analysis request failed: {resp.status_code}"}
        data = resp.json()
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return data
        time.sleep(5)
    return {"error": "Timed out waiting for VirusTotal results"}


def _fetch_existing_file_report(file_hash):
    """Fetch existing report if VT returns 409 for duplicate file."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    resp = requests.get(url, headers=VT_HEADERS)
    if resp.status_code == 200:
        data = resp.json()
        vt_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}
        return _normalize_results(vt_stats, ai_summary, note="Fetched from existing VT report")
    return {"error": f"Failed to fetch existing report: {resp.status_code}", "details": resp.text}


def scan_apk(file_path):
    try:
        if not VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key missing."}

        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            vt_resp = requests.post(VT_SCAN_URL, headers=VT_HEADERS, files=files)

        if vt_resp.status_code == 409:
            # Duplicate file, fetch by hash
            file_hash = vt_resp.json().get("error", {}).get("sha256")
            if file_hash:
                return _fetch_existing_file_report(file_hash)
            return {"error": "VT 409 conflict: file already exists, no hash returned."}

        if vt_resp.status_code not in (200, 202):
            return {"error": f"VT upload failed: {vt_resp.status_code}", "details": vt_resp.text}

        vt_data = vt_resp.json()
        analysis_id = vt_data.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "No VT analysis ID", "raw": vt_data}

        vt_analysis = _poll_analysis(analysis_id)
        if "error" in vt_analysis:
            return vt_analysis

        vt_stats = vt_analysis.get("data", {}).get("attributes", {}).get("stats", {}) or {}
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}
        return _normalize_results(vt_stats, ai_summary)

    except Exception as e:
        return {"error": f"Exception in scan_apk: {str(e)}"}


def scan_url(target_url):
    try:
        if not VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key missing."}

        url_resp = requests.post(VT_URL_SCAN, headers=VT_HEADERS, data={"url": target_url})
        if url_resp.status_code not in (200, 202):
            return {"error": f"VT URL submission failed: {url_resp.status_code}", "details": url_resp.text}

        vt_data = url_resp.json()
        analysis_id = vt_data.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "No VT URL analysis ID", "raw": vt_data}

        vt_analysis = _poll_analysis(analysis_id)
        if "error" in vt_analysis:
            return vt_analysis

        vt_stats = vt_analysis.get("data", {}).get("attributes", {}).get("stats", {}) or {}
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}
        return _normalize_results(vt_stats, ai_summary)

    except Exception as e:
        return {"error": f"Exception in scan_url: {str(e)}"}

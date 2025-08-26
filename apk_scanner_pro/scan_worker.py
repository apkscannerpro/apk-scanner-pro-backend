import requests
import os
import time
import hashlib
import json

# --- VirusTotal API ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# --- Bitdefender Threat Intelligence (optional, enterprise API) ---
BITDEFENDER_API_KEY = os.getenv("BITDEFENDER_API_KEY")
BITDEFENDER_URL = "https://cloud.threatintelligenceplatform.bitdefender.com/v1/file/report"

# --- AI layer ---
AI_ENABLED = True  # toggle
from openai import OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


def _ai_assistant_summary(report_text: str):
    """
    Use LLM to summarize multi-engine scan into a simple verdict.
    """
    if not client:
        return {"ai_summary": "⚠️ AI not configured. Using raw VT verdicts."}

    try:
        prompt = f"""
        Analyze the following APK scan results and summarize risk level 
        (Safe / Suspicious / Malicious). Be concise and user-friendly.

        Report:
        {report_text}
        """
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150
        )
        return {"ai_summary": resp.choices[0].message.content.strip()}
    except Exception as e:
        return {"ai_summary": f"AI summary failed: {str(e)}"}


def _normalize_results(vt_stats, bd_stats=None, ai_summary=None):
    """
    Normalize data into unified schema.
    """
    result = {
        "verdict": "Safe",
        "virustotal": vt_stats,
        "bitdefender": bd_stats or {},
        "ai": ai_summary or {},
    }

    if vt_stats.get("malicious", 0) > 0 or (bd_stats and bd_stats.get("malicious", 0) > 0):
        result["verdict"] = "Malicious"
    elif vt_stats.get("suspicious", 0) > 0:
        result["verdict"] = "Suspicious"

    return result


def _poll_analysis(analysis_id):
    """Poll VirusTotal until complete."""
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(18):  # up to ~90s
        resp = requests.get(analysis_url, headers=VT_HEADERS)
        if resp.status_code != 200:
            return {"error": f"Analysis request failed: {resp.status_code}"}
        data = resp.json()
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return data
        time.sleep(5)
    return {"error": "Timed out waiting for VirusTotal results"}


def scan_apk(file_path):
    """Scan APK with VirusTotal + Bitdefender + AI summarizer."""
    try:
        if not VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key missing."}

        # --- Upload to VirusTotal ---
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            vt_resp = requests.post(VT_SCAN_URL, headers=VT_HEADERS, files=files)

        if vt_resp.status_code not in (200, 202):
            return {"error": f"VT upload failed: {vt_resp.status_code}", "details": vt_resp.text}

        vt_data = vt_resp.json()
        analysis_id = vt_data.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "No VT analysis ID", "raw": vt_data}

        vt_analysis = _poll_analysis(analysis_id)
        if "error" in vt_analysis:
            return vt_analysis

        vt_stats = vt_analysis.get("data", {}).get("attributes", {}).get("stats", {})

        # --- Bitdefender (optional) ---
        bd_stats = {}
        if BITDEFENDER_API_KEY:
            sha256 = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
            bd_resp = requests.get(
                f"{BITDEFENDER_URL}?apikey={BITDEFENDER_API_KEY}&hash={sha256}"
            )
            if bd_resp.status_code == 200:
                bd_stats = bd_resp.json().get("data", {})
            else:
                bd_stats = {"error": f"Bitdefender API {bd_resp.status_code}"}

        # --- AI summarization ---
        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats, "bd": bd_stats})) if AI_ENABLED else {}

        return _normalize_results(vt_stats, bd_stats, ai_summary)

    except Exception as e:
        return {"error": f"Exception in scan_apk: {str(e)}"}


def scan_url(target_url):
    """Scan URL with VirusTotal + AI summarizer."""
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

        vt_stats = vt_analysis.get("data", {}).get("attributes", {}).get("stats", {})

        ai_summary = _ai_assistant_summary(json.dumps({"vt": vt_stats})) if AI_ENABLED else {}

        return _normalize_results(vt_stats, ai_summary=ai_summary)

    except Exception as e:
        return {"error": f"Exception in scan_url: {str(e)}"}

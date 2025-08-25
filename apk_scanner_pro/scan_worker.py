import requests
import os
import time

# --- VirusTotal API setup ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # must match Render env
VT_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}


def scan_apk(file_path):
    """
    Uploads an APK to VirusTotal, polls the analysis report,
    and returns a summarized dict.
    """
    try:
        if not VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key is missing. Please check Render env vars."}

        # Upload file to VirusTotal
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            upload_resp = requests.post(VT_SCAN_URL, headers=VT_HEADERS, files=files)

        if upload_resp.status_code not in (200, 202):
            return {
                "error": f"Upload failed: {upload_resp.status_code}",
                "details": upload_resp.text
            }

        data = upload_resp.json()
        analysis_id = data.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "Failed to get analysis ID from VirusTotal", "response": data}

        # Poll for analysis (wait up to ~90s)
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(18):  # 18 * 5s = 90s
            analysis_resp = requests.get(analysis_url, headers=VT_HEADERS)
            if analysis_resp.status_code != 200:
                return {"error": f"Analysis request failed: {analysis_resp.status_code}"}
            analysis = analysis_resp.json()
            status = analysis.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "raw": analysis
                }
            time.sleep(5)

        return {"error": "Timed out waiting for analysis results"}

    except Exception as e:
        return {"error": f"Exception during scan: {str(e)}"}


def scan_url(target_url):
    """
    Submits a URL to VirusTotal, polls the analysis report,
    and returns a summarized dict.
    """
    try:
        if not VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key is missing. Please check Render env vars."}

        # Submit URL for scanning
        url_resp = requests.post(
            VT_URL_SCAN,
            headers=VT_HEADERS,
            data={"url": target_url}
        )

        if url_resp.status_code not in (200, 202):
            return {
                "error": f"URL submission failed: {url_resp.status_code}",
                "details": url_resp.text
            }

        data = url_resp.json()
        analysis_id = data.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "Failed to get analysis ID from VirusTotal", "response": data}

        # Poll for analysis (wait up to ~90s)
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(18):
            analysis_resp = requests.get(analysis_url, headers=VT_HEADERS)
            if analysis_resp.status_code != 200:
                return {"error": f"Analysis request failed: {analysis_resp.status_code}"}
            analysis = analysis_resp.json()
            status = analysis.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "raw": analysis
                }
            time.sleep(5)

        return {"error": "Timed out waiting for analysis results"}

    except Exception as e:
        return {"error": f"Exception during scan: {str(e)}"}

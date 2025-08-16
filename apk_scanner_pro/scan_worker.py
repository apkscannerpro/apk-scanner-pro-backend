import requests
import os

# --- VirusTotal API setup ---
# Hardcoded API key for now (later you can move it to Render env vars)
VIRUSTOTAL_API_KEY = "6668945fd6178fffbaed43eae32ed42d21c2f2904f5b97908df087983632c411"
VT_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}


def scan_apk(file_path):
    """
    Uploads an APK to VirusTotal, fetches the analysis report, 
    and returns it as a dict.
    """
    try:
        # Upload file
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            upload_resp = requests.post(VT_SCAN_URL, headers=VT_HEADERS, files=files)

        if upload_resp.status_code not in (200, 202):
            return {"error": f"Upload failed: {upload_resp.status_code} {upload_resp.text}"}

        data = upload_resp.json()
        analysis_id = data.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "Failed to get analysis ID from VirusTotal"}

        # Poll for analysis
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(10):  # poll up to 10 times
            analysis_resp = requests.get(analysis_url, headers=VT_HEADERS)
            if analysis_resp.status_code != 200:
                return {"error": f"Analysis request failed: {analysis_resp.status_code}"}
            analysis = analysis_resp.json()
            status = analysis.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return analysis
        return {"error": "Timed out waiting for analysis results"}

    except Exception as e:
        return {"error": f"Exception during scan: {str(e)}"}

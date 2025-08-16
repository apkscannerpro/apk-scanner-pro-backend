import requests
import os

VT_API_KEY = os.getenv("VT_API_KEY")

def scan_apk(file_path):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key is missing. Please set VT_API_KEY in Render environment variables."}

    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": VT_API_KEY,
    }

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(url, headers=headers, files=files)
            if response.status_code in (200, 201):
                return response.json()
            else:
                return {"error": response.text, "status_code": response.status_code}
    except Exception as e:
        return {"error": str(e)}

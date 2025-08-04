import requests
import os

VT_API_KEY = os.getenv("VT_API_KEY")

def scan_apk(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": VT_API_KEY,
    }
    with open(file_path, "rb") as f:
        files = {"file": (file_path, f)}
        response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": response.text}

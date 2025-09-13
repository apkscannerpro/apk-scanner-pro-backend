import os
import json
import csv
import subprocess
import threading
from datetime import datetime

LEADS_LOCK = threading.Lock()

def _save_lead(name, email, source):
    """Save lead into Subscribers folder + auto-push to GitHub."""
    subs_dir = os.getenv("SUBSCRIBERS_PATH", "apk_scanner_pro/Subscribers")
    subs_json = os.path.join(subs_dir, "subscribers.json")
    subs_csv = os.path.join(subs_dir, "subscribers.csv")
    os.makedirs(subs_dir, exist_ok=True)

    with LEADS_LOCK:
        # Load existing JSON
        data = []
        if os.path.exists(subs_json):
            try:
                with open(subs_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = []

        # Deduplicate by email
        if any((sub.get("email") or "").strip().lower() == (email or "").strip().lower() for sub in data):
            return  # Skip duplicates

        # Record
        record = {
            "name": name or "",
            "email": email,
            "source": source,
            "date": datetime.utcnow().isoformat()
        }
        data.append(record)

        # Write JSON
        with open(subs_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        # Write CSV
        new_file = not os.path.exists(subs_csv)
        try:
            with open(subs_csv, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["name", "email", "source", "date"])
                if new_file:
                    writer.writeheader()
                writer.writerow(record)
        except Exception as e:
            print(f"⚠️ CSV write failed: {e}")

        # -----------------------------
        # Commit + Push to GitHub
        # -----------------------------
        try:
            repo_path = os.path.dirname(os.path.dirname(__file__))  # project root
            branch = os.getenv("GITHUB_BRANCH", "main")

            # Git identity
            subprocess.run(["git", "config", "--global", "user.name", os.getenv("GITHUB_USER", "apkscannerpro")], check=True)
            subprocess.run(["git", "config", "--global", "user.email", os.getenv("GITHUB_EMAIL", "support@apkscannerpro.com")], check=True)

            # Stage, commit, push
            subprocess.run(["git", "-C", repo_path, "add", subs_json, subs_csv], check=True)
            subprocess.run(["git", "-C", repo_path, "commit", "-m", f"Add subscriber {record['email']}"], check=True)
            subprocess.run(["git", "-C", repo_path, "push", "origin", branch], check=True)

            print(f"✅ Lead pushed to GitHub: {record['email']}")
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Git push failed: {e}")
        except Exception as e:
            print(f"⚠️ Unexpected Git error: {e}")

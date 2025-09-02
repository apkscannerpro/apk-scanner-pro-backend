from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import uuid
import requests
import sqlite3
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge, BadRequest
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
import threading
import smtplib
from email.mime.text import MIMEText
import json

# Workers
from .scan_worker import scan_apk as scan_apk_file, scan_url
from .report_generator import generate_report, generate_summary

# -------------------------------------------------------------------------------
# Flask setup
# -------------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")

# Allow cross-origin for the main API endpoints
CORS(app, resources={
    r"/scan*": {"origins": "*"},
    r"/scan-result/*": {"origins": "*"},
    r"/scan-stats": {"origins": "*"},
    r"/subscribe": {"origins": "*"},
})

# Increase upload limit to 500 MB
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------------------------------------------------------------------------------
# Database (quota + jobs)
# -------------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "quota.db")

def db_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = db_conn()
    c = conn.cursor()
    # Quota
    c.execute("""
        CREATE TABLE IF NOT EXISTS quota (
            id INTEGER PRIMARY KEY,
            date TEXT,
            used_scans INTEGER
        )
    """)
    if c.execute("SELECT COUNT(*) FROM quota").fetchone()[0] == 0:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        c.execute("INSERT INTO quota (id, date, used_scans) VALUES (1, ?, 0)", (today,))
    # Jobs
    c.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            result TEXT,
            error TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def reset_if_new_day():
    conn = db_conn()
    c = conn.cursor()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    row = c.execute("SELECT date FROM quota WHERE id=1").fetchone()
    if row and row[0] != today:
        c.execute("UPDATE quota SET date=?, used_scans=? WHERE id=1", (today, 0))
        conn.commit()
    conn.close()

def get_used_scans():
    conn = db_conn()
    c = conn.cursor()
    used = c.execute("SELECT used_scans FROM quota WHERE id=1").fetchone()[0]
    conn.close()
    return used

def increment_scans(count=1):
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE quota SET used_scans = used_scans + ? WHERE id=1", (count,))
    conn.commit()
    conn.close()

# --- Jobs helpers ---
def jobs_insert(job_id: str):
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "INSERT INTO jobs (id, status, created_at) VALUES (?, ?, ?)",
        (job_id, "pending", datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()

def jobs_set_done(job_id: str, result_dict: dict):
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "UPDATE jobs SET status=?, result=?, error=NULL WHERE id=?",
        ("done", json.dumps(result_dict), job_id)
    )
    conn.commit()
    conn.close()

def jobs_set_error(job_id: str, error_msg: str):
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "UPDATE jobs SET status=?, error=?, result=NULL WHERE id=?",
        ("error", error_msg, job_id)
    )
    conn.commit()
    conn.close()

def jobs_get(job_id: str):
    conn = db_conn()
    c = conn.cursor()
    row = c.execute("SELECT status, result, error FROM jobs WHERE id=?", (job_id,)).fetchone()
    conn.close()
    if not row:
        return None
    status, result_json, error = row
    out = {"status": status}
    if status == "done" and result_json:
        try:
            out["result"] = json.loads(result_json)
        except Exception:
            out["result"] = None
    if error:
        out["error"] = error
    return out

# -------------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------------
def is_direct_apk_url(url: str) -> bool:
    return url.lower().split("?")[0].endswith(".apk")

def download_apk_to_tmp(url: str) -> str:
    safe_name = secure_filename(url.split("/")[-1] or f"file-{uuid.uuid4()}.apk")
    if not safe_name.lower().endswith(".apk"):
        safe_name += ".apk"
    local_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4()}_{safe_name}")
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
    return local_path

def send_report_via_email(email_to, scan_result):
    """Send professional plain-text branded email."""
    try:
        smtp_host = os.getenv("SMTP_SERVER", "smtpout.secureserver.net")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("EMAIL_USER")
        smtp_pass = os.getenv("EMAIL_PASS")
        if not (smtp_user and smtp_pass):
            raise RuntimeError("SMTP credentials missing")

        summary = generate_summary(scan_result)
        report_text = generate_report(scan_result)

        email_body = f"""
{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
{os.getenv("COMPANY_NAME", "APK Scanner Pro")} - Security Report

Summary:
{summary}

Detailed Report:
{report_text}

---
Protect your device with Bitdefender:
{os.getenv("BITDEFENDER_AFFILIATE_LINK", "https://bitdefender.com")}
        
This report was generated by APK Scanner Pro
Website: https://apkscannerpro.com
Support: support@apkscannerpro.com
"""

        msg = MIMEText(email_body, "plain")
        msg["Subject"] = "🔍 APK Scanner Pro - Security Report"
        msg["From"] = smtp_user
        msg["To"] = email_to

        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, [email_to], msg.as_string())
        return True
    except Exception as e:
        print("Email sending failed:", e)
        return False

def save_subscriber(email: str):
    """Save subscribers to subscribers/subscribers.json"""
    subs_file = os.path.join(os.path.dirname(__file__), "subscribers", "subscribers.json")
    os.makedirs(os.path.dirname(subs_file), exist_ok=True)

    data = []
    if os.path.exists(subs_file):
        try:
            with open(subs_file, "r") as f:
                data = json.load(f)
        except Exception:
            data = []

    if email not in data:
        data.append(email)
        with open(subs_file, "w") as f:
            json.dump(data, f, indent=2)

# -------------------------------------------------------------------------------
# Async job system
# -------------------------------------------------------------------------------
EXECUTOR = ThreadPoolExecutor(max_workers=int(os.getenv("WORKERS", "4")))
JOB_LOCK = threading.Lock()

def _start_job(target_fn, *args, **kwargs):
    job_id = str(uuid.uuid4())
    jobs_insert(job_id)

    def _run():
        try:
            result = target_fn(*args, **kwargs)
            jobs_set_done(job_id, result)
        except Exception as e:
            jobs_set_error(job_id, str(e))

    EXECUTOR.submit(_run)
    return job_id

def _finalize_scan(scan_result, user_email):
    if isinstance(scan_result, dict) and "error" in scan_result:
        return {"error": scan_result.get("error", "Scan failed")}

    increment_scans()
    email_status = None
    if user_email:
        email_status = "sent" if send_report_via_email(user_email, scan_result) else "failed"
        save_subscriber(user_email)

    used = get_used_scans()
    FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))
    return {
        "report": generate_summary(scan_result),
        "scan_count_today": used,
        "free_scans_remaining": max(0, FREE_LIMIT - used),
        "email_status": email_status,
        "paddle_checkout_link": os.getenv("PADDLE_CHECKOUT_LINK"),
    }

def _scan_job_file(user_email=None, tmp_path=None):
    try:
        scan_result = scan_apk_file(tmp_path)
        return _finalize_scan(scan_result, user_email)
    finally:
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

def _scan_job_url(user_email=None, url_param=None):
    if is_direct_apk_url(url_param):
        local = download_apk_to_tmp(url_param)
        try:
            scan_result = scan_apk_file(local)
        finally:
            try:
                if os.path.exists(local):
                    os.remove(local)
            except Exception:
                pass
    else:
        scan_result = scan_url(url_param)
    return _finalize_scan(scan_result, user_email)

# -------------------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/refund-policy")
def refund_policy():
    return render_template("refund-policy.html")

@app.route("/thank-you")
def thank_you():
    return render_template("thank-you.html")

@app.route("/scan-stats")
def scan_stats():
    reset_if_new_day()
    used = get_used_scans()
    FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))
    return jsonify({
        "free_scans_remaining": max(0, FREE_LIMIT - used),
        "scan_count_today": used,
    })

@app.route("/scan-async", methods=["POST"])
def scan_async():
    reset_if_new_day()
    used = get_used_scans()
    FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))

    if used >= FREE_LIMIT:
        return jsonify({
            "error": "Daily free scan limit reached.",
            "payment_required": True,
            "paddle_checkout_link": os.getenv("PADDLE_CHECKOUT_LINK")
        }), 403

    json_body = request.get_json(silent=True) or {}
    form = request.form or {}

    user_email = form.get("email") or json_body.get("email")
    url_param = (
        (form.get("apk_url") or form.get("apk_link") or "")
        or (json_body.get("apk_url") or json_body.get("apk_link") or "")
    ).strip()

    apk_file = None
    if "apk" in request.files and request.files["apk"].filename:
        apk_file = request.files["apk"]
    elif "file" in request.files and request.files["file"].filename:
        apk_file = request.files["file"]

    if not user_email:
        return jsonify({"error": "Email is required"}), 400

    if apk_file:
        filename = secure_filename(apk_file.filename or f"upload-{uuid.uuid4()}.apk")
        tmp_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4()}_{filename}")
        apk_file.save(tmp_path)
        job_id = _start_job(_scan_job_file, user_email=user_email, tmp_path=tmp_path)
    elif url_param:
        job_id = _start_job(_scan_job_url, user_email=user_email, url_param=url_param)
    else:
        return jsonify({"error": "No APK file or apk_url provided"}), 400

    return jsonify({"job_id": job_id})

@app.route("/scan-result/<job_id>")
def scan_result_poll(job_id):
    job = jobs_get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404

    if job["status"] == "done":
        result = job.get("result") or {}
        flattened = {"status": "done"}
        flattened.update(result)
        return jsonify(flattened)

    if job["status"] == "error":
        return jsonify({"status": "error", "error": job.get("error", "unknown error")})

    return jsonify({"status": "pending"})

def save_subscriber(name: str, email: str):
    """Save subscribers to Subscribers/subscribers.json"""
    subs_file = os.path.join(os.path.dirname(__file__), "Subscribers", "subscribers.json")
    os.makedirs(os.path.dirname(subs_file), exist_ok=True)

    data = []
    if os.path.exists(subs_file):
        try:
            with open(subs_file, "r") as f:
                data = json.load(f)
        except Exception:
            data = []

    # Prevent duplicate by email
    if not any(sub.get("email") == email for sub in data):
        data.append({"name": name, "email": email})
        with open(subs_file, "w") as f:
            json.dump(data, f, indent=2)


@app.route("/subscribe", methods=["POST"])
def subscribe():
    json_body = request.get_json(silent=True) or {}
    name = request.form.get("name") or json_body.get("name", "").strip()
    email = request.form.get("email") or json_body.get("email", "").strip()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    save_subscriber(name, email)
    return jsonify({"ok": True, "message": "Subscribed successfully!"})


@app.route("/ping")
def ping():
    return jsonify({"status": "ok"})

# -------------------------------------------------------------------------------
# Error handling
# -------------------------------------------------------------------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    return jsonify({"error": "File too large. Max 500MB."}), 413

@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def handle_500(e):
    return jsonify({"error": "Internal Server Error"}), 500

# -------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))


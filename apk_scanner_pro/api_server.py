from flask import Flask, request, jsonify, send_file, render_template
import os
import logging
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

# Workers
from .scan_worker import scan_apk as scan_apk_file, scan_url
from .report_generator import generate_report

# -------------------------------------------------------------------------------
# Flask setup
# -------------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------------------------------------------------------------------------------
# Database for daily scan quota
# -------------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "quota.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS quota (
            id INTEGER PRIMARY KEY,
            date TEXT,
            used_scans INTEGER
        )
    """)
    if c.execute("SELECT COUNT(*) FROM quota").fetchone()[0] == 0:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        c.execute("INSERT INTO quota (date, used_scans) VALUES (?, ?)", (today, 0))
    conn.commit()
    conn.close()

def reset_if_new_day():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    row = c.execute("SELECT date FROM quota WHERE id=1").fetchone()
    if row and row[0] != today:
        c.execute("UPDATE quota SET date=?, used_scans=? WHERE id=1", (today, 0))
        conn.commit()
    conn.close()

def get_used_scans():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    used = c.execute("SELECT used_scans FROM quota WHERE id=1").fetchone()[0]
    conn.close()
    return used

def increment_scans(count=1):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE quota SET used_scans = used_scans + ? WHERE id=1", (count,))
    conn.commit()
    conn.close()

init_db()

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
    try:
        smtp_host = os.getenv("SMTP_SERVER")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("EMAIL_USER")
        smtp_pass = os.getenv("EMAIL_PASS")
        sender_email = smtp_user

        report_text = generate_report(scan_result)
        msg = MIMEText(report_text)
        msg["Subject"] = "APK Scanner Pro Report"
        msg["From"] = sender_email
        msg["To"] = email_to

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(sender_email, [email_to], msg.as_string())
        return True
    except Exception as e:
        print("Email sending failed:", e)
        return False

# -------------------------------------------------------------------------------
# Async job system
# -------------------------------------------------------------------------------
EXECUTOR = ThreadPoolExecutor(max_workers=int(os.getenv("WORKERS", "4")))
JOB_STORE = {}
JOB_LOCK = threading.Lock()

def _start_job(target_fn, *args, **kwargs):
    job_id = str(uuid.uuid4())
    with JOB_LOCK:
        JOB_STORE[job_id] = {"status": "pending"}
    def _run():
        try:
            result = target_fn(*args, **kwargs)
            with JOB_LOCK:
                JOB_STORE[job_id] = {"status": "done", "result": result}
        except Exception as e:
            with JOB_LOCK:
                JOB_STORE[job_id] = {"status": "error", "error": str(e)}
    EXECUTOR.submit(_run)
    return job_id

def _get_job(job_id):
    with JOB_LOCK:
        return JOB_STORE.get(job_id)

def _finalize_scan(scan_result, user_email):
    if isinstance(scan_result, dict) and "error" in scan_result:
        return {"error": scan_result.get("error", "Scan failed")}
    increment_scans()
    email_status = None
    if user_email:
        email_status = "sent" if send_report_via_email(user_email, scan_result) else "failed"
    used = get_used_scans()
    FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))
    return {
        "report": generate_report(scan_result),
        "scan_count_today": used,
        "free_scans_remaining": max(0, FREE_LIMIT - used),
        "email_status": email_status,
        "paddle_checkout_link": os.getenv("PADDLE_CHECKOUT_LINK")
    }

def _scan_job_file(user_email=None, tmp_path=None):
    try:
        scan_result = scan_apk_file(tmp_path)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
    return _finalize_scan(scan_result, user_email)

def _scan_job_url(user_email=None, url_param=None):
    if is_direct_apk_url(url_param):
        local = download_apk_to_tmp(url_param)
        try:
            scan_result = scan_apk_file(local)
        finally:
            if os.path.exists(local):
                os.remove(local)
    else:
        scan_result = scan_url(url_param)
    return _finalize_scan(scan_result, user_email)

# -------------------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------------------
@app.route("/")
def home(): return render_template("index.html")

@app.route("/scan-stats")
def scan_stats():
    reset_if_new_day()
    used = get_used_scans()
    FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))
    return jsonify({
        "free_scans_remaining": max(0, FREE_LIMIT - used),
        "scan_count_today": used
    })

@app.route("/scan-async", methods=["POST"])
def scan_async():
    reset_if_new_day()
    used = get_used_scans()
    FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))

    if used >= FREE_LIMIT:
        return jsonify({"error": "Daily free scan limit reached.", "payment_required": True, "paddle_checkout_link": os.getenv("PADDLE_CHECKOUT_LINK")}), 403

    json_body = request.get_json(silent=True) or {}
    form = request.form
    user_email = form.get("email") or json_body.get("email")
    url_param = (form.get("apk_link") or json_body.get("apk_url") or "").strip()

    apk_file = None
    if "apk" in request.files and request.files["apk"].filename:
        apk_file = request.files["apk"]
    elif "file" in request.files and request.files["file"].filename:
        apk_file = request.files["file"]

    if apk_file:
        filename = secure_filename(apk_file.filename or "")
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
    job = _get_job(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify(job)

@app.route("/subscribe", methods=["POST"])
def subscribe():
    json_body = request.get_json(silent=True) or {}
    email = request.form.get("email") or json_body.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400
    return jsonify({"ok": True, "message": "Subscribed successfully!"})

# -------------------------------------------------------------------------------
# Static pages for /privacy, /terms, /refund-policy, /pricing, /thank-you
# -------------------------------------------------------------------------------
@app.route("/privacy")
def privacy(): return render_template("privacy.html")

@app.route("/terms")
def terms(): return render_template("terms.html")

@app.route("/refund-policy")
def refund_policy(): return render_template("refund-policy.html")

@app.route("/pricing")
def pricing(): return render_template("pricing.html")

@app.route("/thank-you")
def thank_you(): return render_template("thank-you.html")

# Optional catch-all for any other HTML page in /templates
@app.route("/<page>")
def any_page(page):
    try:
        return render_template(f"{page}.html")
    except:
        return "Page not found", 404

# -------------------------------------------------------------------------------
# Error handling
# -------------------------------------------------------------------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    return jsonify({"error": "File too large"}), 413

@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify({"error": "Bad request"}), 400

# -------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))

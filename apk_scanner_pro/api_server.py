from flask import Flask, request, jsonify, render_template
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
import csv  # <-- added

# Workers
from .scan_worker import scan_apk_file, scan_url
from .report_generator import generate_report, generate_summary

# -------------------------------------------------------------------------------
# Flask setup
# -------------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")

CORS(app, resources={
    r"/scan*": {"origins": "*"},
    r"/scan-result/*": {"origins": "*"},
    r"/scan-stats": {"origins": "*"},
    r"/subscribe": {"origins": "*"},
})

app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------------------------------------------------------------------------------
# Database (quota + jobs + premium logs)
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
            used_free_scans INTEGER,
            used_basic_scans INTEGER,
            used_premium_scans INTEGER
        )
    """)
    # Initialize row if empty
    if c.execute("SELECT COUNT(*) FROM quota").fetchone()[0] == 0:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        c.execute(
            "INSERT INTO quota (id, date, used_free_scans, used_basic_scans, used_premium_scans) VALUES (1, ?, 0, 0, 0)",
            (today,)
        )
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
    # Premium logs
    c.execute("""
        CREATE TABLE IF NOT EXISTS premium_logs (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            payment_ref TEXT,
            created_at TEXT NOT NULL
        )
    """)
    # Basic-paid logs
    c.execute("""
        CREATE TABLE IF NOT EXISTS basic_logs (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            payment_ref TEXT,
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

    # Ensure quota row exists
    c.execute("SELECT id, date FROM quota WHERE id=1")
    row = c.fetchone()

    if not row:
        # Insert fresh row if missing
        c.execute("INSERT INTO quota (id, date, used_free_scans, used_premium_scans) VALUES (1, ?, 0, 0)", (today,))
    elif row[1] != today:
        # Reset if new day
        c.execute("UPDATE quota SET date=?, used_free_scans=0, used_premium_scans=0 WHERE id=1", (today,))

    conn.commit()
    conn.close()


def get_used_scans():
    """Return dict with free + premium used scans"""
    conn = db_conn()
    c = conn.cursor()
    row = c.execute("SELECT used_free_scans, used_premium_scans FROM quota WHERE id=1").fetchone()
    conn.close()
    return {"free": row[0], "premium": row[1]} if row else {"free": 0, "premium": 0}


def increment_free_scans(count=1):
    reset_if_new_day()
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE quota SET used_free_scans = used_free_scans + ? WHERE id=1", (count,))
    conn.commit()
    conn.close()


def increment_premium_scans(count=1, email=None, payment_ref=None):
    """Increment premium counter and log customer details."""
    reset_if_new_day()
    conn = db_conn()
    c = conn.cursor()
    # Update quota
    c.execute("UPDATE quota SET used_premium_scans = used_premium_scans + ? WHERE id=1", (count,))
    # Log transaction if details provided
    if email:
        c.execute(
            "INSERT INTO premium_logs (id, email, payment_ref, created_at) VALUES (?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                email,
                payment_ref or "",
                datetime.now(timezone.utc).isoformat()
            )
        )
    conn.commit()
    conn.close()


def increment_basic_scans(count=1, email=None, payment_ref=None):
    """Increment basic-paid counter and log customer details."""
    reset_if_new_day()
    conn = db_conn()
    c = conn.cursor()
    # Update quota
    c.execute("UPDATE quota SET used_basic_scans = used_basic_scans + ? WHERE id=1", (count,))
    # Log transaction if details provided
    if email:
        c.execute(
            "INSERT INTO basic_logs (id, email, payment_ref, created_at) VALUES (?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                email,
                payment_ref or "",
                datetime.now(timezone.utc).isoformat()
            )
        )
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

def send_report_via_email(email_to, scan_result, file_name_or_url=None, premium=False):
    try:
        smtp_host = os.getenv("SMTP_SERVER", "smtpout.secureserver.net")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("EMAIL_USER")
        smtp_pass = os.getenv("EMAIL_PASS")
        if not (smtp_user and smtp_pass):
            raise RuntimeError("SMTP credentials missing")

        # -------------------
        # Determine content
        # -------------------
        if premium:
            summary = generate_summary(scan_result)
            report_text = generate_report(scan_result)
            scan_type_notice = "🔐 Premium Scan — Full Detailed Report"
        else:
            summary = generate_summary(scan_result)
            report_text = "Full detailed report is available for premium scans only. Upgrade to premium to get complete results."
            scan_type_notice = "🔓 Free Scan — Summary Only"

        company = os.getenv("COMPANY_NAME", "APK Scanner Pro")
        affiliate = os.getenv("BITDEFENDER_AFFILIATE_LINK", "https://bitdefender.com")
        website = "https://apkscannerpro.com"
        support = "support@apkscannerpro.com"

        verdict = (scan_result or {}).get("verdict", "Unknown")
        vt = (scan_result or {}).get("virustotal", {})
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        undetected = vt.get("undetected", 0)
        harmless = vt.get("harmless", 0)

        email_body = f"""
📅 {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} — {scan_type_notice}
🏢 {company} — Security Report

━━━━━━━━━━━━━━━━━━━━━━━
🔍 SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━
{summary}

━━━━━━━━━━━━━━━━━━━━━━━
🧾 SCAN DETAILS
━━━━━━━━━━━━━━━━━━━━━━━
📂 Target: {file_name_or_url or 'N/A'}
✅ Final Verdict: {verdict}
🧪 VirusTotal Stats → Malicious: {malicious} | Suspicious: {suspicious} | Undetected: {undetected} | Harmless: {harmless}

━━━━━━━━━━━━━━━━━━━━━━━
🛡️ DETAILED REPORT
━━━━━━━━━━━━━━━━━━━━━━━
{report_text}

━━━━━━━━━━━━━━━━━━━━━━━
📌 RECOMMENDATIONS
━━━━━━━━━━━━━━━━━━━━━━━
1) Install apps only from trusted sources.
2) Keep Android & apps updated.
3) Re-scan new app versions before installing.
4) Use a reputable mobile AV for real-time protection.
5) Back up important data regularly.

━━━━━━━━━━━━━━━━━━━━━━━
🔐 Protect your device with Bitdefender
{affiliate}

Report generated by {company}
🌐 {website}
📧 {support}
"""

        subject_line = f"🔍 {company} Report — {file_name_or_url}" if file_name_or_url else f"🔍 {company} — Security Report"

        msg = MIMEText(email_body, "plain", "utf-8")
        msg["Subject"] = subject_line
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

# Leads file write lock (to avoid races across threads)
LEADS_LOCK = threading.Lock()

def _save_lead(name, email, source):
    """Save leads to Subscribers/subscribers.json and subscribers.csv (deduped)."""
    subs_dir = os.path.join(os.path.dirname(__file__), "Subscribers")
    subs_json = os.path.join(subs_dir, "subscribers.json")
    subs_csv = os.path.join(subs_dir, "subscribers.csv")
    os.makedirs(subs_dir, exist_ok=True)

    with LEADS_LOCK:
        # Load existing JSON data
        data = []
        if os.path.exists(subs_json):
            try:
                with open(subs_json, "r") as f:
                    data = json.load(f)
            except Exception:
                data = []

        # Dedupe check
        if any((sub.get("email") or "").strip().lower() == (email or "").strip().lower() for sub in data):
            return  # already present → no duplicate write

        # Append into JSON
        record = {
            "name": name or "",
            "email": email,
            "source": source,
            "date": datetime.utcnow().isoformat()
        }
        data.append(record)
        with open(subs_json, "w") as f:
            json.dump(data, f, indent=2)

        # Append into CSV (create header if new)
        new_file = not os.path.exists(subs_csv)
        try:
            with open(subs_csv, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["name", "email", "source", "date"])
                if new_file:
                    writer.writeheader()
                writer.writerow(record)
        except Exception as e:
            # CSV issues should not break API flow; log to stdout
            print(f"CSV write failed: {e}")

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

def _finalize_scan(scan_result, user_email, file_name_or_url=None, premium=False, payment_ref=None, basic_paid=False):
    """
    Handles email sending and scan result processing.
    Auto-detects quota & payment status.
    """
    if isinstance(scan_result, dict) and "error" in scan_result:
        return {"error": scan_result.get("error", "Scan failed"), "success": False, "email": user_email}

    # --- Determine scan type ---
    if not premium and not basic_paid:
        used = get_used_scans()
        FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))
        if used.get("free", 0) >= FREE_LIMIT:
            basic_paid = True
            payment_ref = "basic_paid"

    if premium and not payment_ref:
        return {"error": "Premium scan requires payment reference.", "success": False, "email": user_email}

    # --- Send email based on scan type ---
    email_sent = send_report_via_email(
        email_to=user_email,
        scan_result=scan_result,
        file_name_or_url=file_name_or_url,
        premium=premium
    )

    # --- Save lead ---
    _save_lead(name="", email=user_email, source="scan_report")

    return {
        "success": email_sent,
        "email": user_email,
        "premium": premium,
        "basic_paid": basic_paid
    }

def _scan_job_file(user_email=None, tmp_path=None, file_name_or_url=None, premium=False, payment_ref=None, basic_paid=False):
    try:
        scan_result = scan_apk_file(tmp_path, premium=premium, payment_ref=payment_ref)
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
        except Exception:
            pass


def _scan_job_url(user_email=None, url_param=None, file_name_or_url=None, premium=False, payment_ref=None, basic_paid=False):
    if is_direct_apk_url(url_param):
        local = download_apk_to_tmp(url_param)
        try:
            scan_result = scan_apk_file(local, premium=premium, payment_ref=payment_ref)
        finally:
            try:
                if os.path.exists(local):
                    os.remove(local)
            except Exception:
                pass
    else:
        scan_result = scan_url(url_param, premium=premium, payment_ref=payment_ref)

    return _finalize_scan(
        scan_result,
        user_email,
        file_name_or_url=file_name_or_url or url_param,
        premium=premium,
        payment_ref=payment_ref,
        basic_paid=basic_paid
    )


# -------------------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------------------
from flask import redirect, Response

@app.route("/")
@app.route("/home")
def home():
    return render_template("index.html")

@app.route("/best-antivirus-for-android")
def blog_antivirus():
    return render_template("best-antivirus-for-android.html")

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

@app.route("/paid-scan", methods=["POST"])
def paid_scan():
    """
    Called after manual payment confirmation (frontend thank-you redirect).
    Unlocks either basic ($1) or premium ($15) scan for the user.
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    # align key name with frontend ("ref")
    payment_ref = data.get("payment_ref") or data.get("ref")
    mode = data.get("mode", "basic")  # "basic" (default) or "premium"

    if not email or not payment_ref:
        return jsonify({"ok": False, "error": "Missing email or payment reference"}), 400

    if mode == "premium":
        increment_premium_scans(1, email=email, payment_ref=payment_ref)
        return jsonify({"ok": True, "message": "Premium scan unlocked", "premium": True})
    else:
        increment_basic_scans(1, email=email, payment_ref=payment_ref)
        return jsonify({"ok": True, "message": "Basic scan unlocked", "basic_paid": True})




# Robots.txt (served dynamically)
@app.route("/robots.txt")
def robots_txt():
    content = """User-agent: *
Allow: /

Sitemap: https://www.apkscannerpro.com/sitemap.xml

# AI bots allowed for indexing and retrieval
User-agent: GPTBot
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: CCBot
Allow: /

User-agent: Bytespider
Allow: /
"""
    return Response(content, mimetype="text/plain")

# Dynamic Sitemap.xml
@app.route("/sitemap.xml")
def sitemap_xml():
    pages = [
        {"loc": "https://www.apkscannerpro.com/", "priority": "1.0"},
        {"loc": "https://www.apkscannerpro.com/home", "priority": "0.9"},
        {"loc": "https://www.apkscannerpro.com/privacy"},
        {"loc": "https://www.apkscannerpro.com/terms"},
        {"loc": "https://www.apkscannerpro.com/pricing"},
        {"loc": "https://www.apkscannerpro.com/refund-policy"},
        {"loc": "https://www.apkscannerpro.com/thank-you"},
        {"loc": "https://www.apkscannerpro.com/best-antivirus-for-android"},
    ]

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for page in pages:
        xml += "  <url>\n"
        xml += f"    <loc>{page['loc']}</loc>\n"
        if "priority" in page:
            xml += f"    <priority>{page['priority']}</priority>\n"
        xml += "  </url>\n"
    xml += "</urlset>\n"

    return Response(xml, mimetype="application/xml")

@app.before_request
def enforce_https_and_www():
    # Force HTTPS
    if request.headers.get("X-Forwarded-Proto", "http") != "https":
        return redirect(request.url.replace("http://", "https://"), code=301)

    # Force www (always go to https://www.apkscannerpro.com)
    host = request.host
    if host == "apkscannerpro.com":
        return redirect("https://www.apkscannerpro.com" + request.full_path, code=301)

# -----------------------------
# Scan stats endpoint (for frontend quota display)
# -----------------------------
@app.route("/scan-stats")
def scan_stats():
    # Always make sure quota row exists and reset if new day
    reset_if_new_day()

    # Get used scan counts
    used = get_used_scans()  # {"free": X, "premium": Y, "basic_paid": Z}
    used_free = int(used.get("free", 0))
    used_premium = int(used.get("premium", 0))
    used_basic_paid = int(used.get("basic_paid", 0))

    # Daily limits from environment (fallback to defaults)
    FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", 200))
    PREMIUM_LIMIT = int(os.getenv("MAX_PREMIUM_SCANS_PER_DAY", 50))

    # Remaining scans (never below zero)
    free_remaining = max(0, FREE_LIMIT - used_free)
    premium_remaining = max(0, PREMIUM_LIMIT - used_premium)

    # Return JSON payload for frontend
    return jsonify({
        "status": "ok",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "free_scans_remaining": free_remaining,
        "premium_scans_remaining": premium_remaining,
        "used_free_scans": used_free,
        "used_basic_paid_scans": used_basic_paid,   # ✅ NEW counter
        "used_premium_scans": used_premium,
        "free_limit": FREE_LIMIT,
        "premium_limit": PREMIUM_LIMIT
    })


@app.route("/scan-async", methods=["POST"])
def scan_async():
    try:
        # Reset counters if new day
        reset_if_new_day()

        # Fetch used counters
        used = get_used_scans()  # {"free": X, "premium": Y, "basic_paid": Z}
        used_free = used.get("free", 0)
        used_premium = used.get("premium", 0)
        used_basic_paid = used.get("basic_paid", 0)

        FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))
        PREMIUM_LIMIT = int(os.getenv("MAX_PREMIUM_SCANS_PER_DAY", "50"))
        BASIC_PAID_LIMIT = int(os.getenv("MAX_BASIC_PAID_SCANS_PER_DAY", "500"))

        # Parse request
        json_body = request.get_json(silent=True) or {}
        form = request.form or {}

        user_email = form.get("email") or json_body.get("email")
        payment_ref = form.get("payment_ref") or json_body.get("payment_ref")
        url_param = (form.get("apk_url") or form.get("apk_link") or ""
                     or json_body.get("apk_url") or json_body.get("apk_link") or "").strip()

        apk_file = None
        if "apk" in request.files and request.files["apk"].filename:
            apk_file = request.files["apk"]
        elif "file" in request.files and request.files["file"].filename:
            apk_file = request.files["file"]

        if not user_email:
            return jsonify({"error": "Email is required"}), 400
        if not apk_file and not url_param:
            return jsonify({"error": "No APK file or apk_url provided"}), 400

        # Flags
        premium = False
        basic_paid = False

        if "premium" in form:
            premium = form.get("premium").lower() == "true"
        elif "premium" in json_body:
            premium = json_body.get("premium") is True

        if "basic_paid" in form:
            basic_paid = form.get("basic_paid").lower() == "true"
        elif "basic_paid" in json_body:
            basic_paid = json_body.get("basic_paid") is True

        # -----------------------------
        # Automatic quota handling
        # -----------------------------
        if premium:
            # Require payment_ref for premium
            if not payment_ref:
                return jsonify({
                    "error": "Email and payment reference are required for premium scans.",
                    "payment_required": True,
                    "premium": True
                }), 403
            if used_premium >= PREMIUM_LIMIT:
                return jsonify({
                    "error": "Daily premium scan limit reached.",
                    "payment_required": True,
                    "premium": True
                }), 403

        elif basic_paid:
            # Paid basic scans
            if not payment_ref:
                payment_ref = "basic_paid"
            if used_basic_paid >= BASIC_PAID_LIMIT:
                return jsonify({
                    "error": "Daily basic paid scan limit reached.",
                    "payment_required": True,
                    "basic_paid": True
                }), 403

        else:
            # Free scans
            if used_free >= FREE_LIMIT:
                # Auto-upgrade to basic-paid
                basic_paid = True
                payment_ref = "basic_paid"

        # -----------------------------
        # Start scan job
        # -----------------------------
        if apk_file:
            filename = secure_filename(apk_file.filename or f"upload-{uuid.uuid4()}.apk")
            tmp_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4()}_{filename}")
            apk_file.save(tmp_path)
            job_id = _start_job(
                _scan_job_file,
                user_email=user_email,
                tmp_path=tmp_path,
                file_name_or_url=filename,
                premium=premium,
                payment_ref=payment_ref,
                basic_paid=basic_paid
            )
        else:
            job_id = _start_job(
                _scan_job_url,
                user_email=user_email,
                url_param=url_param,
                file_name_or_url=url_param,
                premium=premium,
                payment_ref=payment_ref,
                basic_paid=basic_paid
            )

        # -----------------------------
        # Increment counters
        # -----------------------------
        if premium:
            increment_premium_scans()
        elif basic_paid:
            increment_basic_paid_scans()
        else:
            increment_free_scans()

        return jsonify({
            "job_id": job_id,
            "premium": premium,
            "basic_paid": basic_paid
        })

    except Exception as e:
        print(f"Scan async error: {e}")
        return jsonify({"error": "Internal Server Error"}), 500


@app.route("/scan-result/<job_id>")
def scan_result_poll(job_id):
    job = jobs_get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404

    if job["status"] == "done":
        result = job.get("result") or {}
        return jsonify({
            "status": "done",
            "success": result.get("success", False),
            "email": result.get("email")
        })

    if job["status"] == "error":
        return jsonify({"status": "error", "error": job.get("error", "unknown error")})

    return jsonify({"status": "pending"})

@app.route("/subscribe", methods=["POST"])
def subscribe():
    json_body = request.get_json(silent=True) or {}
    name = request.form.get("name") or json_body.get("name", "").strip()
    email = request.form.get("email") or json_body.get("email", "").strip()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    _save_lead(name=name, email=email, source="newsletter")
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
# Fallback route: redirect unknown paths to home
# -------------------------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return redirect("/home")

# -------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))



































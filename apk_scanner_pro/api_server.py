from flask import Flask, request, jsonify, render_template
import os
import uuid
import requests
import sqlite3
import traceback
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge, BadRequest
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart  # <-- Added for Brevo support
import json
import csv  # <-- keep CSV support for subscribers
import subprocess  # <-- NEW: needed for Git commit/push
from threading import Lock  # <-- NEW: for thread-safe writes
from apk_scanner_pro.lead_manager import _save_lead

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
# Database (quota + jobs + premium logs + basic logs)
# -------------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "quota.db")

def db_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = db_conn()
    c = conn.cursor()

    # Quota table (with free, basic, premium counters)
    c.execute("""
        CREATE TABLE IF NOT EXISTS quota (
            id INTEGER PRIMARY KEY,
            date TEXT,
            used_free_scans INTEGER DEFAULT 0,
            used_basic_scans INTEGER DEFAULT 0,
            used_premium_scans INTEGER DEFAULT 0
        )
    """)

    # Initialize quota row if empty
    if c.execute("SELECT COUNT(*) FROM quota").fetchone()[0] == 0:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        c.execute("""
            INSERT INTO quota (id, date, used_free_scans, used_basic_scans, used_premium_scans)
            VALUES (1, ?, 0, 0, 0)
        """, (today,))

    # Jobs table (for async scan tracking)
    c.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            result TEXT,
            error TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # Premium logs (records of paid premium scans)
    c.execute("""
        CREATE TABLE IF NOT EXISTS premium_logs (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            payment_ref TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # Basic-paid logs (records of paid basic scans)
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

# Ensure DB exists and quota row initialized at startup
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
        c.execute("""
            INSERT INTO quota (id, date, used_free_scans, used_premium_scans, used_basic_scans)
            VALUES (1, ?, 0, 0, 0)
        """, (today,))
    elif row[1] != today:
        # Reset all counters if new day
        c.execute("""
            UPDATE quota 
            SET date=?, used_free_scans=0, used_premium_scans=0, used_basic_scans=0 
            WHERE id=1
        """, (today,))

    conn.commit()
    conn.close()


def get_used_scans():
    """Return dict with free, premium, and basic used scans"""
    conn = db_conn()
    c = conn.cursor()
    row = c.execute(
        "SELECT used_free_scans, used_premium_scans, used_basic_scans FROM quota WHERE id=1"
    ).fetchone()
    conn.close()
    return {"free": row[0], "premium": row[1], "basic_paid": row[2]} if row else {"free": 0, "premium": 0, "basic_paid": 0}


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


def increment_basic_paid_scans(count=1, email=None, payment_ref=None):
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

def send_report_via_email(email_to=None, scan_result=None, file_name_or_url=None, premium=False, **kwargs):
    """
    Send report via SMTP (Brevo). Backwards-compatible: accepts email_to= or to_email=.
    Returns True on success, False on failure.
    """
    try:
        # Accept alias names
        to_email = email_to or kwargs.get("to_email") or kwargs.get("to") or kwargs.get("recipient")
        if not to_email:
            raise RuntimeError("No recipient email provided to send_report_via_email")

        # -------------------
        # Load SMTP settings from Render variables
        # -------------------
        smtp_host = os.getenv("SMTP_SERVER", "smtp-relay.brevo.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USERNAME")  # Brevo login (your SMTP username/email)
        smtp_pass = os.getenv("SMTP_PASSWORD")  # Brevo SMTP key (password)
        smtp_from = os.getenv("SMTP_FROM", "support@apkscannerpro.com")  # branded sender

        if not (smtp_user and smtp_pass):
            raise RuntimeError("SMTP credentials missing — check Render variables")

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
        vt = (scan_result or {}).get("virustotal", {}) or {}
        # Defensive extraction (some results may be nested)
        malicious = vt.get("malicious", vt.get("malicious_count", 0))
        suspicious = vt.get("suspicious", vt.get("suspicious_count", 0))
        undetected = vt.get("undetected", vt.get("undetected_count", 0))
        harmless = vt.get("harmless", vt.get("harmless_count", 0))

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
        msg["From"] = smtp_from
        msg["To"] = to_email

        # -------------------
        # Send via Brevo SMTP
        # -------------------
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [to_email], msg.as_string())

        return True

    except Exception as e:
        print("Email sending failed:", e)
        return False
        

def _init_repo():
    """Ensure a local git repo is ready for commits + pushes."""
    repo_url = f"https://{os.getenv('GITHUB_TOKEN')}@github.com/{os.getenv('GITHUB_REPO')}.git"
    branch = os.getenv("GITHUB_BRANCH", "main")
    user = os.getenv("GITHUB_USER", "apkscannerpro")
    email = os.getenv("GITHUB_EMAIL", "support@apkscannerpro.com")

    try:
        # If no .git folder, init
        if not os.path.exists(".git"):
            subprocess.run(["git", "init"], check=True)
            subprocess.run(["git", "checkout", "-b", branch], check=True)
            subprocess.run(["git", "remote", "add", "origin", repo_url], check=True)
        else:
            # If origin doesn’t exist, add it
            remotes = subprocess.run(
                ["git", "remote"], capture_output=True, text=True, check=True
            ).stdout.split()
            if "origin" not in remotes:
                subprocess.run(["git", "remote", "add", "origin", repo_url], check=True)
            else:
                subprocess.run(["git", "remote", "set-url", "origin", repo_url], check=True)

        # Always reset config in case container restarts
        subprocess.run(["git", "config", "--global", "user.name", user], check=True)
        subprocess.run(["git", "config", "--global", "user.email", email], check=True)

        print("✅ Repo initialized & remote set")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Repo init failed: {e}")


# -------------------------------------------------------------------------------
# Async job system
# -------------------------------------------------------------------------------
EXECUTOR = ThreadPoolExecutor(max_workers=int(os.getenv("WORKERS", "4")))
JOB_LOCK = threading.Lock()

def _start_job(target_fn, *args, **kwargs):
    job_id = str(uuid.uuid4())

    # Try to insert job entry (best-effort)
    try:
        jobs_insert(job_id)
    except Exception as e:
        print(f"[WARN] jobs_insert failed for {job_id}: {e}")

    def _run():
        try:
            result = target_fn(*args, **kwargs)

            # ✅ Ensure dict result
            if not isinstance(result, dict):
                print(f"[ERROR] Non-dict result from scan: {result}")
                result = {"status": "error", "message": "Scan function failed"}

            # ✅ Strict: require VT data
            if (
                not result.get("virustotal")
                and result.get("status") != "error"
            ):
                print(f"[ERROR] Missing virustotal data in result: {result}")
                result = {"status": "error", "message": "No VirusTotal data returned"}

            # ✅ Ensure JSON-serializable
            try:
                json.dumps(result)
            except TypeError:
                cleaned = {}
                for k, v in result.items():
                    try:
                        json.dumps({k: v})
                        cleaned[k] = v
                    except TypeError:
                        cleaned[k] = str(v)
                result = cleaned

            jobs_set_done(job_id, result)

        except Exception as e:
            tb = traceback.format_exc()
            print(f"[ERROR] Job {job_id} crashed: {e}\n{tb}")
            try:
                jobs_set_error(job_id, f"Exception: {str(e)}")
            except Exception as db_e:
                print(f"[ERROR] Failed to record job error for {job_id}: {db_e}")

    EXECUTOR.submit(_run)
    return job_id



def _finalize_scan(scan_result, user_email, file_name_or_url=None,
                   premium=False, payment_ref=None, basic_paid=False):
    """
    Normalize and finalize scan results.
    Sends email + saves lead.
    Always returns a strict normalized dict.
    """
    print(f"[DEBUG] Finalizing scan for {user_email}, file={file_name_or_url}")
    print(f"[DEBUG] Raw scan_result: {scan_result}")

    # --- Normalize early ---
    if not scan_result or not isinstance(scan_result, dict):
        print("[WARN] scan_result missing or not dict, normalizing...")
        scan_result = {}

    verdict = scan_result.get("verdict", "Unknown")
    message = scan_result.get("message") or scan_result.get("error", "")
    vt_data = scan_result.get("virustotal") or scan_result.get("data") or {}

    # If VirusTotal timed out or failed
    if scan_result.get("status") == "error" or "error" in scan_result:
        print(f"[WARN] Normalizing error scan_result: {message}")
        verdict = "Unknown"

    # --- Send email ---
    email_sent = False
    try:
        email_sent = send_report_via_email(
            email_to=user_email,   # ✅ consistent arg name
            scan_result={
                "verdict": verdict,
                "virustotal": vt_data,
                "message": message
            },
            file_name_or_url=file_name_or_url or "APK File",
            premium=premium,
            payment_ref=payment_ref
        )
        print(f"[DEBUG] Email sent status: {email_sent} to {user_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send email to {user_email}: {e}")

    # --- Save lead ---
    try:
        _save_lead(name="", email=user_email, source="scan_report")
        print(f"[DEBUG] Lead saved for {user_email}")
    except Exception as e:
        print(f"[WARN] Failed to save lead: {e}")

    # --- Always return normalized dict (strict keys) ---
    return {
        "success": bool(email_sent),
        "email": user_email,
        "premium": premium,
        "basic_paid": basic_paid,
        "verdict": verdict,
        "message": message,
        "virustotal": vt_data
    }


def _scan_job_file(user_email=None, tmp_path=None, file_name_or_url=None, premium=False, payment_ref=None, basic_paid=False):
    try:
        try:
            scan_result = scan_apk_file(tmp_path, premium=premium, payment_ref=payment_ref)
            print(f"[DEBUG] File scan raw result for {file_name_or_url}: {scan_result}")
        except Exception as e:
            print(f"[ERROR] scan_apk_file failed for {file_name_or_url}: {e}")
            scan_result = {"error": str(e)}

        return _finalize_scan(
            scan_result,
            user_email,
            file_name_or_url=file_name_or_url,
            premium=premium,
            payment_ref=payment_ref,
            basic_paid=basic_paid
        )
    finally:
        if tmp_path:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                    print(f"[DEBUG] Temp file deleted: {tmp_path}")
            except Exception as e:
                print(f"[WARN] Failed to delete tmp file {tmp_path}: {e}")


def _scan_job_url(user_email=None, url_param=None, file_name_or_url=None, premium=False, payment_ref=None, basic_paid=False):
    try:
        scan_result = {}
        if is_direct_apk_url(url_param):
            local = download_apk_to_tmp(url_param)
            try:
                scan_result = scan_apk_file(local, premium=premium, payment_ref=payment_ref)
                print(f"[DEBUG] URL file scan result for {file_name_or_url or url_param}: {scan_result}")
            finally:
                if os.path.exists(local):
                    os.remove(local)
        else:
            try:
                scan_result = scan_url(url_param, premium=premium, payment_ref=payment_ref)
                print(f"[DEBUG] URL scan result for {file_name_or_url or url_param}: {scan_result}")
            except Exception as e:
                print(f"[ERROR] scan_url failed for {url_param}: {e}")
                scan_result = {"error": str(e)}

        return _finalize_scan(
            scan_result,
            user_email,
            file_name_or_url=file_name_or_url or url_param,
            premium=premium,
            payment_ref=payment_ref,
            basic_paid=basic_paid
        )
    except Exception as e:
        print(f"[ERROR] _scan_job_url failed totally for {url_param}: {e}")
        return _finalize_scan(
            {"error": str(e)},
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

@app.route("/about-us")
def about_us():
    return render_template("about-us.html")

@app.route("/apk-virus-signs")
def apk_virus_signs():
    return render_template("apk-virus-signs.html")

@app.route("/scan-apk-files-online")
def scan_apk_files_online():
    return render_template("scan-apk-files-online.html")

@app.route("/blog")
def blog():
    return render_template("blog.html")

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

@app.route('/ads.txt')
def ads_txt():
    return app.send_static_file('ads.txt')

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
        increment_basic_paid_scans(1, email=email, payment_ref=payment_ref)
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
    today = datetime.utcnow().date().isoformat()  # YYYY-MM-DD

    pages = [
        {"loc": "https://www.apkscannerpro.com/", "priority": "1.0"},
        {"loc": "https://www.apkscannerpro.com/home", "priority": "0.9"},
        {"loc": "https://www.apkscannerpro.com/privacy"},
        {"loc": "https://www.apkscannerpro.com/terms"},
        {"loc": "https://www.apkscannerpro.com/pricing"},
        {"loc": "https://www.apkscannerpro.com/refund-policy"},
        {"loc": "https://www.apkscannerpro.com/thank-you"},
        {"loc": "https://www.apkscannerpro.com/best-antivirus-for-android"},
        {"loc": "https://www.apkscannerpro.com/about-us"},
        {"loc": "https://www.apkscannerpro.com/apk-virus-signs"},
        {"loc": "https://www.apkscannerpro.com/scan-apk-files-online"},
        {"loc": "https://www.apkscannerpro.com/blog", "priority": "0.8"},
    ]

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for page in pages:
        xml += "  <url>\n"
        xml += f"    <loc>{page['loc']}</loc>\n"
        xml += f"    <lastmod>{today}</lastmod>\n"
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
    try:
        # Always make sure quota row exists and reset if new day
        reset_if_new_day()

        # Get used scan counts
        used = get_used_scans()  # {"free": X, "premium": Y, "basic_paid": Z}
        used_free = int(used.get("free", 0))
        used_premium = int(used.get("premium", 0))
        used_basic_paid = int(used.get("basic_paid", 0))

        # Daily limits from environment (fallback to defaults)
        FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", 50))
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
    except Exception as e:
        print(f"Scan stats error: {e}")
        return jsonify({"error": "Unable to fetch scan stats"}), 500


@app.route("/scan-async", methods=["POST"])
def scan_async():
    """
    Handle APK scan request (file upload or URL).
    Applies quota checks, starts scan job, and increments counters.
    """
    try:
        # -----------------------------
        # Ensure upload directory exists
        # -----------------------------
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        # -----------------------------
        # Reset counters if new day
        # -----------------------------
        reset_if_new_day()

        # -----------------------------
        # Fetch used counters
        # -----------------------------
        used = get_used_scans() or {}
        used_free = used.get("free", 0)
        used_premium = used.get("premium", 0)
        used_basic_paid = used.get("basic_paid", 0)

        FREE_LIMIT = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "50"))
        PREMIUM_LIMIT = int(os.getenv("MAX_PREMIUM_SCANS_PER_DAY", "50"))
        BASIC_PAID_LIMIT = int(os.getenv("MAX_BASIC_PAID_SCANS_PER_DAY", "500"))

        # -----------------------------
        # Parse request
        # -----------------------------
        json_body = request.get_json(silent=True) or {}
        form = request.form or {}

        user_email = form.get("email") or json_body.get("email")
        payment_ref = form.get("payment_ref") or json_body.get("payment_ref")

        url_param = (
            form.get("apk_url") or form.get("apk_link") or
            json_body.get("apk_url") or json_body.get("apk_link") or ""
        ).strip()

        apk_file = None
        if "apk" in request.files and request.files["apk"].filename:
            apk_file = request.files["apk"]
        elif "file" in request.files and request.files["file"].filename:
            apk_file = request.files["file"]

        if not user_email:
            return jsonify({"error": "Email is required"}), 400
        if not apk_file and not url_param:
            return jsonify({"error": "No APK file or apk_url provided"}), 400

        # -----------------------------
        # Scan type flags
        # -----------------------------
        premium = str(form.get("premium") or json_body.get("premium") or "").lower() == "true"
        basic_paid = str(form.get("basic_paid") or json_body.get("basic_paid") or "").lower() == "true"

        # -----------------------------
        # Quota handling
        # -----------------------------
        if premium:
            if not payment_ref:
                return jsonify({
                    "error": "Payment reference is required for premium scans.",
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
            if not payment_ref:
                payment_ref = "basic_paid"
            if used_basic_paid >= BASIC_PAID_LIMIT:
                return jsonify({
                    "error": "Daily basic paid scan limit reached.",
                    "payment_required": True,
                    "basic_paid": True
                }), 403

        else:
            if used_free >= FREE_LIMIT:
                # Auto-switch to paid
                basic_paid = True
                payment_ref = "basic_paid"
                

        # -----------------------------
        # Start scan job
        # -----------------------------
        try:
            if apk_file:
                filename = secure_filename(apk_file.filename or f"upload-{uuid.uuid4()}.apk")
                tmp_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4()}_{filename}")
                apk_file.save(tmp_path)
                print(f"[DEBUG] File scan started: {tmp_path}")

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
                print(f"[DEBUG] URL scan started: {url_param}")

                job_id = _start_job(
                    _scan_job_url,
                    user_email=user_email,
                    url_param=url_param,
                    file_name_or_url=url_param,
                    premium=premium,
                    payment_ref=payment_ref,
                    basic_paid=basic_paid
                )

        except Exception as e:
            print(f"[ERROR] Scan job start failed: {e}")
            return jsonify({"error": "Failed to start scan"}), 500

        # -----------------------------
        # Increment counters
        # -----------------------------
        try:
            if premium:
                increment_premium_scans()
            elif basic_paid:
                increment_basic_paid_scans()
            else:
                increment_free_scans()
        except Exception as e:
            print(f"[ERROR] Failed to increment scan counters: {e}")

        # -----------------------------
        # Return success
        # -----------------------------
        return jsonify({
            "job_id": job_id,
            "premium": premium,
            "basic_paid": basic_paid
        })

    except Exception as e:
        print(f"[ERROR] scan_async exception: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/scan-result/<job_id>")
def scan_result_poll(job_id):
    try:
        job = jobs_get(job_id)
        if not job:
            return jsonify({"status": "error", "success": False, "message": "Job not found"}), 404

        if job["status"] == "done":
            result = job.get("result") or {}

            # --- Normalize ---
            normalized = {
                "success": bool(result.get("success", False)),
                "email": result.get("email"),
                "verdict": result.get("verdict", "Unknown"),
                "message": result.get("message", ""),
                "virustotal": result.get("virustotal", {}),
                "premium": result.get("premium", False),
                "basic_paid": result.get("basic_paid", False)
            }

            return jsonify({
                "status": "done",
                **normalized
            })

        if job["status"] == "error":
            return jsonify({
                "status": "error",
                "success": False,
                "verdict": "Unknown",
                "message": job.get("error", "Unknown error"),
                "virustotal": {}
            })

        # Still processing
        return jsonify({"status": "pending", "success": False})

    except Exception as e:
        print(f"[ERROR] scan_result_poll exception: {e}")
        return jsonify({
            "status": "error",
            "success": False,
            "verdict": "Unknown",
            "message": "Internal Server Error",
            "virustotal": {}
        }), 500



@app.route("/subscribe", methods=["POST"])
def subscribe():
    json_body = request.get_json(silent=True) or {}
    name = request.form.get("name") or (json_body.get("name", "")).strip()
    email = request.form.get("email") or (json_body.get("email", "")).strip()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Save + auto-push handled inside _save_lead
    _save_lead(name=name, email=email, source="newsletter")

    return jsonify({"ok": True, "message": "Subscribed successfully!"})

# Initialize git repo on startup
_init_repo()

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
































































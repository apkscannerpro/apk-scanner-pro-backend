import os
import sqlite3
import logging
import smtplib, ssl
from datetime import datetime
from flask import Flask, request, jsonify, send_file, render_template, abort

# ---------- CONFIG ----------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
# Render persistent disk recommendation (set this path as your Disk mount in Render)
DATA_DIR = os.environ.get("DATA_DIR", "/opt/render/project/src/var")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "scan_data.sqlite")

UPLOAD_DIR = "/tmp"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Limits & pricing
FREE_LIMIT_PER_IP_PER_DAY = int(os.environ.get("FREE_LIMIT_PER_IP_PER_DAY", "200"))
PAID_SCANS_PER_50C = int(os.environ.get("PAID_SCANS_PER_50C", "50"))
PAID_SCANS_PER_1USD = int(os.environ.get("PAID_SCANS_PER_1USD", "120"))

# Placeholders you’ll replace later
PAY_LINK = os.environ.get("PAY_LINK", "#")  # e.g., your Payoneer Checkout URL
BITDEFENDER_AFFILIATE = os.environ.get("BITDEFENDER_AFFILIATE", "#")
ADSENSE_ID = os.environ.get("ADSENSE_ID", "")  # e.g., ca-pub-xxxxxxxxxxxxxxxx

# Email notify (optional)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
NOTIFY_EMAIL = os.environ.get("NOTIFY_EMAIL", "support@apkscannerpro.com")

# ---------- FLASK ----------
app = Flask(__name__, static_folder=os.path.join(APP_DIR, "..", "static"),
            template_folder=os.path.join(APP_DIR, "templates"))
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB

# ---------- LOGGING ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ---------- DB SETUP ----------
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS usage (
            ip TEXT NOT NULL,
            date TEXT NOT NULL,
            free_used INTEGER NOT NULL DEFAULT 0,
            paid_balance INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (ip, date)
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            amount_usd REAL,
            scans_added INTEGER,
            source TEXT,
            created_at TEXT
        );
    """)
    conn.commit()
    return conn

db = get_db()

def today_utc():
    return datetime.utcnow().strftime("%Y-%m-%d")

def client_ip():
    # Honor reverse proxy headers (Render/Cloudflare)
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def get_or_create_usage(ip):
    d = today_utc()
    cur = db.cursor()
    cur.execute("SELECT free_used, paid_balance FROM usage WHERE ip=? AND date=?", (ip, d))
    row = cur.fetchone()
    if row is None:
        cur.execute("INSERT INTO usage (ip, date, free_used, paid_balance) VALUES (?, ?, 0, 0)", (ip, d))
        db.commit()
        return 0, 0
    return row[0], row[1]

def update_usage(ip, free_used=None, paid_balance=None):
    d = today_utc()
    # ensure row exists
    _ = get_or_create_usage(ip)
    sets = []
    vals = []
    if free_used is not None:
        sets.append("free_used=?")
        vals.append(free_used)
    if paid_balance is not None:
        sets.append("paid_balance=?")
        vals.append(paid_balance)
    vals.extend([ip, d])
    sql = "UPDATE usage SET " + ", ".join(sets) + " WHERE ip=? AND date=?"
    cur = db.cursor()
    cur.execute(sql, vals)
    db.commit()

def add_payment(ip, amount_usd, scans_added, source="manual"):
    cur = db.cursor()
    cur.execute("INSERT INTO payments (ip, amount_usd, scans_added, source, created_at) VALUES (?, ?, ?, ?, ?)",
                (ip, amount_usd, scans_added, source, datetime.utcnow().isoformat()))
    db.commit()

def send_email(subject, body):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and NOTIFY_EMAIL):
        logging.info("Email not configured; skipping send. Subject: %s Body: %s", subject, body)
        return
    msg = f"From: {SMTP_USER}\r\nTo: {NOTIFY_EMAIL}\r\nSubject: {subject}\r\n\r\n{body}"
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [NOTIFY_EMAIL], msg.encode("utf-8"))

# ---------- BUSINESS LOGIC ----------
from scan_worker import scan_apk
from report_generator import generate_report

def allowed_file(filename):
    return filename.lower().endswith(".apk")

@app.route("/scan", methods=["POST"])
def scan():
    ip = client_ip()
    free_used, paid_balance = get_or_create_usage(ip)

    # enforce limits
    if "apk" not in request.files:
        return jsonify({"error": "No APK file uploaded"}), 400

    apk = request.files["apk"]
    if not apk.filename or not allowed_file(apk.filename):
        return jsonify({"error": "Only .apk files are allowed"}), 400

    # If over free limit and no paid balance -> paywall
    if free_used >= FREE_LIMIT_PER_IP_PER_DAY and paid_balance <= 0:
        return jsonify({
            "error": "Free scan limit reached for today.",
            "payment_required": True,
            "pricing": {
                "usd_0_50": f"{PAID_SCANS_PER_50C} scans",
                "usd_1_00": f"{PAID_SCANS_PER_1USD} scans"
            },
            "pay_link": PAY_LINK
        }), 402  # Payment Required (non-standard but meaningful)

    # Save & scan
    filepath = os.path.join(UPLOAD_DIR, apk.filename)
    apk.save(filepath)
    logging.info("Scanning file from IP %s: %s", ip, apk.filename)

    result = scan_apk(filepath)
    if isinstance(result, dict) and result.get("error"):
        logging.error("Scan error for %s: %s", ip, result["error"])
        return jsonify(result), 500

    report = generate_report(result)

    # Update counters
    if free_used < FREE_LIMIT_PER_IP_PER_DAY:
        update_usage(ip, free_used=free_used + 1)
    else:
        update_usage(ip, paid_balance=paid_balance - 1)

    # fresh counts after update
    free_used, paid_balance = get_or_create_usage(ip)
    remaining_free = max(0, FREE_LIMIT_PER_IP_PER_DAY - free_used)

    return jsonify({
        "report": report,
        "quota": {
            "free_remaining": remaining_free,
            "paid_balance": paid_balance
        }
    })

@app.route("/scan-stats", methods=["GET"])
def scan_stats():
    ip = client_ip()
    free_used, paid_balance = get_or_create_usage(ip)
    return jsonify({
        "ip": ip,
        "free_limit": FREE_LIMIT_PER_IP_PER_DAY,
        "free_used": free_used,
        "free_remaining": max(0, FREE_LIMIT_PER_IP_PER_DAY - free_used),
        "paid_balance": paid_balance,
        "date": today_utc()
    })

@app.route("/payment/notify", methods=["POST"])
def payment_notify():
    """
    v1: manual confirmation endpoint.
    Body (JSON):
      { "plan": "50c" | "1usd", "ip": "optional-ip", "txid": "optional-tx", "source": "payoneer|kofi|other" }
    If ip omitted, we credit the requester’s IP.
    """
    data = request.get_json(silent=True) or {}
    plan = str(data.get("plan", "")).lower().strip()
    source = (data.get("source") or "manual").lower()
    ip = data.get("ip") or client_ip()
    txid = data.get("txid") or "n/a"

    if plan not in {"50c", "1usd"}:
        return jsonify({"error": "Invalid plan. Use '50c' or '1usd'."}), 400

    scans_added = PAID_SCANS_PER_50C if plan == "50c" else PAID_SCANS_PER_1USD
    amount_usd = 0.50 if plan == "50c" else 1.00

    free_used, paid_balance = get_or_create_usage(ip)
    update_usage(ip, paid_balance=paid_balance + scans_added)
    add_payment(ip, amount_usd, scans_added, source=source)

    # Email notify (optional)
    try:
        send_email(
            subject=f"[APK Scanner Pro] Payment received ({plan}) from {ip}",
            body=f"TX: {txid}\nSource: {source}\nIP: {ip}\nAdded scans: {scans_added}\nDate: {today_utc()}"
        )
    except Exception as e:
        logging.exception("Email send failed: %s", e)

    logging.info("Credited %s scans to %s via plan %s (txid=%s)", scans_added, ip, plan, txid)
    return jsonify({"ok": True, "ip": ip, "paid_balance_added": scans_added})

@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def home():
    return render_template(
        "index.html",
        pay_link=PAY_LINK or "#",
        bitdefender_aff=BITDEFENDER_AFFILIATE or "#",
        adsense_id=ADSENSE_ID
    )

@app.route("/ping", methods=["GET"])
def ping():
    return "pong"

# robots & sitemap served from /static
@app.route("/robots.txt")
def robots():
    static_path = os.path.join(app.static_folder, "robots.txt")
    if not os.path.exists(static_path):
        abort(404)
    return send_file(static_path, mimetype="text/plain")

@app.route("/sitemap.xml")
def sitemap():
    static_path = os.path.join(app.static_folder, "sitemap.xml")
    if not os.path.exists(static_path):
        abort(404)
    return send_file(static_path, mimetype="application/xml")

if __name__ == "__main__":
    # Local dev; in Render use gunicorn or python start command
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

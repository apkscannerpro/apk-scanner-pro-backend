from flask import Flask, request, jsonify, send_file, render_template
import os
import json
import logging
import uuid
import requests
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge, BadRequest
from flask_cors import CORS

# Workers (relative imports for package safety)
from .scan_worker import scan_apk as scan_apk_file, scan_url
from .report_generator import generate_report, send_report_via_email

# ------------------------------------------------------------------------------
# Flask setup
# ------------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")

# Enable CORS for API endpoints (safe for same-origin; helpful if UI is separate)
CORS(app, resources={
    r"/scan": {"origins": "*"},
    r"/scan-stats": {"origins": "*"},
    r"/subscribe": {"origins": "*"}
})

# Max upload size: ~150MB (typical APKs << 150MB)
app.config["MAX_CONTENT_LENGTH"] = 150 * 1024 * 1024

# Storage paths (Render uses ephemeral FS)
UPLOAD_DIR = "/tmp/uploads"
DATA_DIR = "/tmp/data"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

SCAN_DATA_FILE = os.path.join(DATA_DIR, "scan_data.json")
SUBSCRIBERS_FILE = os.path.join(DATA_DIR, "subscribers.txt")

# Business rules
MAX_FREE_SCANS_PER_DAY = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("apk_scanner_pro")

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def client_ip():
    return (request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown").split(",")[0].strip()

def load_scan_data():
    if not os.path.exists(SCAN_DATA_FILE):
        return {"by_ip": {}, "last_reset": ""}
    try:
        with open(SCAN_DATA_FILE, "r") as f:
            return json.load(f)
    except Exception:
        log.exception("Failed to read scan_data.json; resetting.")
        return {"by_ip": {}, "last_reset": ""}

def save_scan_data(data):
    try:
        with open(SCAN_DATA_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        log.exception("Failed to write scan_data.json")

def reset_daily_scan_count():
    data = load_scan_data()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    if data.get("last_reset") != today:
        data = {"by_ip": {}, "last_reset": today}
        save_scan_data(data)
    return data

def increment_ip_count(ip):
    data = reset_daily_scan_count()
    by_ip = data.setdefault("by_ip", {})
    by_ip[ip] = by_ip.get(ip, 0) + 1
    save_scan_data(data)
    return by_ip[ip]

def count_for_ip(ip):
    data = reset_daily_scan_count()
    return data.get("by_ip", {}).get(ip, 0)

def remaining_for_ip(ip):
    return max(0, MAX_FREE_SCANS_PER_DAY - count_for_ip(ip))

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

# ------------------------------------------------------------------------------
# Context Processor
# ------------------------------------------------------------------------------
from datetime import datetime as _dt
@app.context_processor
def inject_current_year():
    return {"current_year": _dt.utcnow().year}

# ------------------------------------------------------------------------------
# Routes: pages
# ------------------------------------------------------------------------------
@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/privacy", methods=["GET"])
def privacy():
    return render_template("privacy.html")

@app.route("/terms", methods=["GET"])
def terms():
    return render_template("terms.html")

@app.route("/pricing", methods=["GET"])
def pricing():
    return render_template("pricing.html")

@app.route("/refund-policy", methods=["GET"])
def refund_policy():
    return render_template("refund-policy.html")

@app.route("/thank-you", methods=["GET"])
def thank_you():
    return render_template("thank-you.html")

# ------------------------------------------------------------------------------
# Routes: API
# ------------------------------------------------------------------------------
@app.route("/scan-stats", methods=["GET"])
def scan_stats():
    ip = client_ip()
    return jsonify({
        "free_scans_remaining": remaining_for_ip(ip),
        "scan_count_today": count_for_ip(ip),
        "reset_at_midnight": True,
        "limit_per_day": MAX_FREE_SCANS_PER_DAY,
        "ip": ip
    })

@app.route("/scan", methods=["POST"])
def scan():
    ip = client_ip()
    reset_daily_scan_count()

    if remaining_for_ip(ip) <= 0:
        return jsonify({"error": "Daily free scan limit reached.", "payment_required": True}), 403

    user_email, apk_file, tmp_path, url_param = None, None, None, None

    try:
        # --- Read body safely regardless of Content-Type
        json_body = request.get_json(silent=True) or {}
        form = request.form

        # --- Get email ---
        user_email = (form.get("email") or json_body.get("email"))

        # --- Handle APK file upload (support multiple field names) ---
        if "apk" in request.files and request.files["apk"].filename:
            apk_file = request.files["apk"]
        elif "file" in request.files and request.files["file"].filename:
            apk_file = request.files["file"]
        else:
            # --- Fallback: check apk_url for URL scan ---
            url_param = (form.get("apk_url") or json_body.get("apk_url"))
            if url_param:
                url_param = url_param.strip()
    except Exception:
        log.exception("Failed to parse incoming request")
        return jsonify({"error": "Invalid request payload"}), 400

    # --- File upload path ---
    if apk_file:
        filename = secure_filename(apk_file.filename or "")
        if not filename.lower().endswith(".apk"):
            return jsonify({"error": "File must be an .apk"}), 400

        tmp_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4()}_{filename}")
        try:
            apk_file.save(tmp_path)
        except Exception:
            log.exception("Failed to save uploaded file")
            return jsonify({"error": "Failed to save uploaded file"}), 500

        log.info(f"[{ip}] Upload received: {filename} -> {tmp_path}")

        try:
            scan_result = scan_apk_file(tmp_path)
        finally:
            try:
                if tmp_path and os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                log.warning("Failed to remove temp file: %s", tmp_path)

    # --- URL scan path ---
    elif url_param:
        log.info(f"[{ip}] URL scan request: {url_param}")
        if is_direct_apk_url(url_param):
            try:
                tmp_path = download_apk_to_tmp(url_param)
                scan_result = scan_apk_file(tmp_path)
            except Exception as e:
                log.exception("Failed to download/scan APK from URL")
                return jsonify({"error": f"Failed to download APK: {e}"}), 400
            finally:
                try:
                    if tmp_path and os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    log.warning("Failed to remove temp file: %s", tmp_path)
        else:
            try:
                scan_result = scan_url(url_param)
            except Exception:
                log.exception("scan_url crashed")
                return jsonify({"error": "URL scanning failed"}), 500
    else:
        return jsonify({"error": "No APK file or apk_url provided"}), 400

    # --- Handle worker errors ---
    if isinstance(scan_result, dict) and "error" in scan_result:
        log.error(f"[{ip}] Worker error: {scan_result['error']}")
        # Make sure error payloads are JSON (front-end expects JSON)
        return jsonify(scan_result), 500

    # --- Generate summary ---
    try:
        report_text = generate_report(scan_result)
    except Exception:
        log.exception("generate_report crashed")
        return jsonify({"error": "Internal scanning error (summary)"}), 500

    # --- Count scans + send email ---
    new_count = increment_ip_count(ip)
    email_status = None
    if user_email:
        try:
            ok = send_report_via_email(user_email, scan_result)
            email_status = "sent" if ok else "failed"
        except Exception:
            log.exception("Email sending failed")
            email_status = "failed"

    log.info(f"[{ip}] Scan OK. used={new_count}, left={remaining_for_ip(ip)}, email={email_status}")
    return jsonify({
        "report": report_text,
        "scan_count_today": new_count,
        "free_scans_remaining": remaining_for_ip(ip),
        "email_status": email_status
    })

@app.route("/subscribe", methods=["POST"])
def subscribe():
    json_body = request.get_json(silent=True) or {}
    email = request.form.get("email") or json_body.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400
    try:
        os.makedirs(os.path.dirname(SUBSCRIBERS_FILE), exist_ok=True)
        with open(SUBSCRIBERS_FILE, "a") as f:
            f.write(email.strip() + "\n")
        log.info(f"New subscriber: {email}")
        # Front-end expects `ok`
        return jsonify({"ok": True, "message": "Subscribed successfully!"})
    except Exception:
        log.exception("Failed to save subscriber email")
        return jsonify({"error": "Failed to save subscription"}), 500

@app.route("/robots.txt")
def robots():
    path = os.path.join(app.static_folder, "robots.txt")
    if os.path.exists(path):
        return send_file(path, mimetype="text/plain")
    return (
        "User-agent: *\nAllow: /\nSitemap: https://apkscannerpro.com/sitemap.xml\n",
        200,
        {"Content-Type": "text/plain"},
    )

@app.route("/sitemap.xml")
def sitemap():
    path = os.path.join(app.static_folder, "sitemap.xml")
    if os.path.exists(path):
        return send_file(path, mimetype="application/xml")
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://apkscannerpro.com/</loc></url>
  <url><loc>https://apkscannerpro.com/privacy</loc></url>
  <url><loc>https://apkscannerpro.com/terms</loc></url>
  <url><loc>https://apkscannerpro.com/pricing</loc></url>
  <url><loc>https://apkscannerpro.com/refund-policy</loc></url>
  <url><loc>https://apkscannerpro.com/thank-you</loc></url>
</urlset>"""
    return sitemap_xml, 200, {"Content-Type": "application/xml"}

@app.route("/ping")
def ping():
    return {"status": "ok"}

# ------------------------------------------------------------------------------
# Error handling (return JSON so front-end doesn't crash on res.json())
# ------------------------------------------------------------------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_413(e):
    # Happens when file exceeds MAX_CONTENT_LENGTH; default is HTML which breaks res.json()
    return jsonify({"error": "File too large. Max size is 150MB."}), 413

@app.errorhandler(BadRequest)
def handle_400(e):
    # Covers malformed form-data/JSON
    return jsonify({"error": "Bad Request"}), 400

@app.errorhandler(500)
def handle_500(e):
    log.exception("Internal server error")
    return jsonify({"error": "Internal Server Error"}), 500

# Entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


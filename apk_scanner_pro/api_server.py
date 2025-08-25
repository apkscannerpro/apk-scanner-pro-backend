from flask import Flask, request, jsonify, send_file, render_template
import os
import json
import logging
import uuid
import requests
from datetime import datetime
from werkzeug.utils import secure_filename

# Import your workers (make sure scan_worker exposes scan_apk_file() and scan_url())
from .scan_worker import scan_apk as scan_apk_file, scan_url
from .report_generator import generate_report, send_report_via_email

# ------------------------------------------------------------------------------
# Flask setup
# ------------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")

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
MAX_FREE_SCANS_PER_DAY = int(os.getenv("MAX_FREE_SCANS_PER_DAY", "200"))  # per IP

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("apk_scanner_pro")

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def client_ip():
    # Respect reverse proxy header if present (Render)
    return (request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown").split(",")[0].strip()

def load_scan_data():
    """Load daily scan stats (per IP) from JSON."""
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
    """Resets counters if UTC day changed."""
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
    used = count_for_ip(ip)
    return max(0, MAX_FREE_SCANS_PER_DAY - used)

def is_direct_apk_url(url: str) -> bool:
    return url.lower().split("?")[0].endswith(".apk")

def download_apk_to_tmp(url: str) -> str:
    """
    Streams a remote .apk to /tmp/uploads and returns the local path.
    Raises an Exception if download fails or content-type is suspicious.
    """
    safe_name = secure_filename(url.split("/")[-1] or f"file-{uuid.uuid4()}.apk")
    if not safe_name.lower().endswith(".apk"):
        safe_name += ".apk"
    local_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4()}_{safe_name}")

    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        # (optional) basic sanity check; don't hard-block if CDN hides type
        content_type = r.headers.get("Content-Type", "")
        # Save to disk
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):  # 1 MB chunks
                if chunk:
                    f.write(chunk)

    return local_path

# ------------------------------------------------------------------------------
# Context Processor to inject current_year
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
    left = remaining_for_ip(ip)
    used = count_for_ip(ip)
    return jsonify({
        "free_scans_remaining": left,
        "scan_count_today": used,
        "reset_at_midnight": True,
        "limit_per_day": MAX_FREE_SCANS_PER_DAY,
        "ip": ip
    })

@app.route("/scan", methods=["POST"])
def scan():
    """
    Accepts either:
      - multipart/form-data with file field `apk` (required .apk)
      - form/json field `apk_url` for URL scans:
          * if URL ends with .apk → we download and do a file scan
          * else → VirusTotal URL analysis (scan_url)
    Optionally takes `email` to send the PDF summary.
    """
    ip = client_ip()
    reset_daily_scan_count()

    # Enforce free limit per IP
    if remaining_for_ip(ip) <= 0:
        return jsonify({
            "error": "Daily free scan limit reached.",
            "payment_required": True
        }), 403

    user_email = None
    apk_file = None
    tmp_path = None
    url_param = None

    # Parse inputs from either multipart/form-data or JSON
    try:
        user_email = (request.form.get("email") or
                      (request.json.get("email") if request.is_json else None))

        if "apk" in request.files and request.files["apk"].filename:
            apk_file = request.files["apk"]
        else:
            # URL mode
            url_param = (request.form.get("apk_url")
                         or (request.json.get("apk_url") if request.is_json else None))
            if url_param:
                url_param = url_param.strip()
    except Exception:
        log.exception("Failed to parse incoming request")
        return jsonify({"error": "Invalid request payload"}), 400

    # --- Branch A: File upload
    if apk_file:
        filename = secure_filename(apk_file.filename or "")
        if not filename.lower().endswith(".apk"):
            return jsonify({"error": "File must be an .apk"}), 400

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        tmp_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4()}_{filename}")
        apk_file.save(tmp_path)

        log.info(f"[{ip}] Upload received: {filename} -> {tmp_path}")

        try:
            scan_result = scan_apk_file(tmp_path)  # VirusTotal FILE analysis
        finally:
            # Always cleanup the temp file
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                log.warning("Temp file cleanup failed", exc_info=True)

    # --- Branch B: URL scan
    elif url_param:
        log.info(f"[{ip}] URL scan request: {url_param}")

        # If it's a direct .apk link, download and scan as file
        if is_direct_apk_url(url_param):
            try:
                tmp_path = download_apk_to_tmp(url_param)
                log.info(f"[{ip}] Downloaded APK from URL -> {tmp_path}")
                scan_result = scan_apk_file(tmp_path)
            except Exception as e:
                log.exception("Failed to download/scan APK from URL")
                return jsonify({"error": f"Failed to download APK: {e}"}), 400
            finally:
                try:
                    if tmp_path and os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    log.warning("Temp file cleanup failed", exc_info=True)
        else:
            # Non-APK URL → VirusTotal URL analysis
            try:
                scan_result = scan_url(url_param)  # VirusTotal URL analysis
            except Exception:
                log.exception("scan_url crashed")
                return jsonify({"error": "URL scanning failed"}), 500

    else:
        return jsonify({"error": "No APK file or apk_url provided"}), 400

    # Handle worker errors
    if isinstance(scan_result, dict) and "error" in scan_result:
        log.error(f"[{ip}] Worker error: {scan_result['error']}")
        return jsonify(scan_result), 500

    # Generate human-readable summary (OpenAI)
    try:
        report_text = generate_report(scan_result)
    except Exception:
        log.exception("generate_report crashed")
        return jsonify({"error": "Internal scanning error (summary)"}), 500

    # Count this successful scan
    new_count = increment_ip_count(ip)
    left = remaining_for_ip(ip)

    # Email (optional)
    email_status = None
    if user_email:
        try:
            ok = send_report_via_email(user_email, scan_result)
            email_status = "sent" if ok else "failed"
        except Exception:
            log.exception("Email sending failed")
            email_status = "failed"

    # Done
    log.info(f"[{ip}] Scan OK. used={new_count}, left={left}, email={email_status}")
    return jsonify({
        "report": report_text,
        "scan_count_today": new_count,
        "free_scans_remaining": left,
        "email_status": email_status
    })

@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form.get("email") or (request.json.get("email") if request.is_json else None)
    if not email:
        return jsonify({"error": "Email is required"}), 400

    try:
        os.makedirs(os.path.dirname(SUBSCRIBERS_FILE), exist_ok=True)
        with open(SUBSCRIBERS_FILE, "a") as f:
            f.write(email.strip() + "\n")
        log.info(f"New subscriber: {email}")
        return jsonify({"message": "Subscribed successfully!"})
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

# Error handling
@app.errorhandler(500)
def handle_500(e):
    log.exception("Internal server error")
    return jsonify({"error": "Internal Server Error"}), 500

# Entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

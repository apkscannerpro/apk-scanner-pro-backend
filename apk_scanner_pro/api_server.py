from flask import Flask, request, jsonify, send_file, render_template
import os
from .scan_worker import scan_apk
from .report_generator import generate_report, send_report_via_email
from datetime import datetime
import json
import logging

# Flask setup
app = Flask(__name__, static_folder="static", template_folder="templates")

# Storage paths (Render uses ephemeral FS, so we put everything under /tmp)
UPLOAD_DIR = "/tmp"
SCAN_DATA_FILE = os.path.join("/tmp", "scan_data.json")
SUBSCRIBERS_FILE = os.path.join("/tmp", "subscribers.txt")

# Business rules
MAX_FREE_SCANS_PER_DAY = 200  # daily free scan limit

# Logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("apk_scanner_pro")


# --- Helpers ---
def load_scan_data():
    """Load daily scan stats from /tmp/scan_data.json"""
    if not os.path.exists(SCAN_DATA_FILE):
        return {"scan_count": 0, "last_reset": ""}
    try:
        with open(SCAN_DATA_FILE, "r") as f:
            return json.load(f)
    except Exception:
        log.exception("Failed to read scan_data.json; resetting.")
        return {"scan_count": 0, "last_reset": ""}


def save_scan_data(data):
    """Save daily scan stats to /tmp/scan_data.json"""
    try:
        with open(SCAN_DATA_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        log.exception("Failed to write scan_data.json")


def reset_daily_scan_count():
    """Resets count if UTC day changed"""
    data = load_scan_data()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    if data.get("last_reset") != today:
        data["scan_count"] = 0
        data["last_reset"] = today
        save_scan_data(data)
    return data


# --- Routes ---
@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def home():
    """Serve frontend landing page"""
    return render_template("index.html")


@app.route("/privacy", methods=["GET"])
def privacy():
    """Serve privacy policy page"""
    return render_template("privacy.html")


@app.route("/terms", methods=["GET"])
def terms():
    """Serve terms of service page"""
    return render_template("terms.html")


@app.route("/scan-stats", methods=["GET"])
def scan_stats():
    """Return remaining free scans for today"""
    data = reset_daily_scan_count()
    return jsonify({
        "free_scans_remaining": max(0, MAX_FREE_SCANS_PER_DAY - data["scan_count"]),
        "scan_count_today": data["scan_count"],
        "reset_at_midnight": True,
        "limit_per_day": MAX_FREE_SCANS_PER_DAY
    })


@app.route("/scan", methods=["POST"])
def scan():
    """Handle APK scan request"""
    data = reset_daily_scan_count()

    # Limit check
    if data["scan_count"] >= MAX_FREE_SCANS_PER_DAY:
        return jsonify({
            "error": "Daily free scan limit reached.",
            "payment_required": True
        }), 403

    # Validate file
    if "apk" not in request.files:
        return jsonify({"error": "No APK file uploaded"}), 400

    apk = request.files["apk"]
    if not apk.filename.lower().endswith(".apk"):
        return jsonify({"error": "File must be an .apk"}), 400

    # Optional: user email
    user_email = request.form.get("email")

    # Save file under /tmp
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(UPLOAD_DIR, apk.filename)
    apk.save(file_path)

    # Perform scan
    try:
        scan_result = scan_apk(file_path)  # calls VirusTotal wrapper
        if isinstance(scan_result, dict) and "error" in scan_result:
            return jsonify(scan_result), 500
        report = generate_report(scan_result)
    except Exception:
        log.exception("scan_apk/generate_report crashed")
        return jsonify({"error": "Internal scanning error"}), 500

    # Update stats
    data["scan_count"] += 1
    save_scan_data(data)

    # Try sending email if provided
    email_status = None
    if user_email:
        try:
            success = send_report_via_email(user_email, scan_result)
            email_status = "sent" if success else "failed"
        except Exception:
            log.exception("Email sending failed")
            email_status = "failed"

    return jsonify({
        "report": report,
        "scan_count_today": data["scan_count"],
        "email_status": email_status
    })


@app.route("/subscribe", methods=["POST"])
def subscribe():
    """Collect emails for newsletter"""
    email = request.form.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    try:
        os.makedirs(os.path.dirname(SUBSCRIBERS_FILE), exist_ok=True)
        with open(SUBSCRIBERS_FILE, "a") as f:
            f.write(email + "\n")
        log.info(f"New subscriber: {email}")
        return jsonify({"message": "Subscribed successfully!"})
    except Exception:
        log.exception("Failed to save subscriber email")
        return jsonify({"error": "Failed to save subscription"}), 500


@app.route("/robots.txt")
def robots():
    """Serve robots.txt"""
    return send_file(os.path.join(app.static_folder, "robots.txt"), mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    """Serve sitemap.xml"""
    return send_file(os.path.join(app.static_folder, "sitemap.xml"), mimetype="application/xml")


@app.route("/ping")
def ping():
    """Health check for Render"""
    return {"status": "ok"}


# --- Error Handling ---
@app.errorhandler(500)
def handle_500(e):
    log.exception("Internal server error")
    return jsonify({"error": "Internal Server Error"}), 500


# Entry point for Render/Gunicorn
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

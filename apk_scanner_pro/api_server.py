from flask import Flask, request, jsonify, send_file, render_template
import os
from scan_worker import scan_apk
from report_generator import generate_report
from datetime import datetime
import json
import logging

# folders are relative to this package path
app = Flask(__name__, static_folder="static", template_folder="templates")

# safer paths for ephemeral Render FS
UPLOAD_DIR = "/tmp"
SCAN_DATA_FILE = os.path.join("/tmp", "scan_data.json")

# business rules
MAX_FREE_SCANS_PER_DAY = 200  # your updated daily free limit

# logging to stdout for Render logs
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("apk_scanner_pro")

# --- helpers ---
def load_scan_data():
    if not os.path.exists(SCAN_DATA_FILE):
        return {"scan_count": 0, "last_reset": ""}
    try:
        with open(SCAN_DATA_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        log.exception("Failed to read scan_data.json; resetting.")
        return {"scan_count": 0, "last_reset": ""}

def save_scan_data(data):
    try:
        with open(SCAN_DATA_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        log.exception("Failed to write scan_data.json")

def reset_daily_scan_count():
    data = load_scan_data()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    if data.get("last_reset") != today:
        data["scan_count"] = 0
        data["last_reset"] = today
        save_scan_data(data)
    return data

# --- routes ---
@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def home():
    # templates/index.html
    return render_template("index.html")

@app.route("/scan-stats", methods=["GET"])
def scan_stats():
    data = reset_daily_scan_count()
    return jsonify({
        "free_scans_remaining": max(0, MAX_FREE_SCANS_PER_DAY - data["scan_count"]),
        "scan_count_today": data["scan_count"],
        "reset_at_midnight": True,
        "limit_per_day": MAX_FREE_SCANS_PER_DAY
    })

@app.route("/scan", methods=["POST"])
def scan():
    data = reset_daily_scan_count()

    if data["scan_count"] >= MAX_FREE_SCANS_PER_DAY:
        # Frontend will show payment modal/options
        return jsonify({
            "error": "Daily free scan limit reached.",
            "payment_required": True
        }), 403

    if "apk" not in request.files:
        return jsonify({"error": "No APK file uploaded"}), 400

    apk = request.files["apk"]
    if not apk.filename.lower().endswith(".apk"):
        return jsonify({"error": "File must be an .apk"}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(UPLOAD_DIR, apk.filename)
    apk.save(file_path)

    try:
        scan_result = scan_apk(file_path)
        if isinstance(scan_result, dict) and "error" in scan_result:
            return jsonify(scan_result), 500
        report = generate_report(scan_result)
    except Exception as e:
        log.exception("scan_apk/generate_report crashed")
        return jsonify({"error": "Internal scanning error"}), 500

    data["scan_count"] += 1
    save_scan_data(data)

    return jsonify({
        "report": report,
        "scan_count_today": data["scan_count"]
    })

@app.route("/robots.txt")
def robots():
    return send_file(os.path.join(app.static_folder, "robots.txt"), mimetype="text/plain")

@app.route("/sitemap.xml")
def sitemap():
    return send_file(os.path.join(app.static_folder, "sitemap.xml"), mimetype="application/xml")

@app.route("/ping")
def ping():
    return {"status": "ok"}

# error handlers for cleaner 500s
@app.errorhandler(500)
def handle_500(e):
    log.exception("Internal server error")
    return jsonify({"error": "Internal Server Error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

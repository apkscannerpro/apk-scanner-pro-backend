from flask import Flask, request, jsonify, send_file, render_template
import os
from scan_worker import scan_apk
from report_generator import generate_report
from datetime import datetime
import json

app = Flask(__name__, static_folder="static", template_folder="templates")

UPLOAD_DIR = "/tmp"
MAX_FREE_SCANS_PER_DAY = 300
SCAN_DATA_FILE = "scan_data.json"

# ✅ Helper: Load scan data
def load_scan_data():
    if not os.path.exists(SCAN_DATA_FILE):
        return {"scan_count": 0, "last_reset": ""}
    with open(SCAN_DATA_FILE, "r") as f:
        return json.load(f)

# ✅ Helper: Save scan data
def save_scan_data(data):
    with open(SCAN_DATA_FILE, "w") as f:
        json.dump(data, f)

# ✅ Reset scan counter daily
def reset_daily_scan_count():
    data = load_scan_data()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    if data.get("last_reset") != today:
        data["scan_count"] = 0
        data["last_reset"] = today
        save_scan_data(data)
    return data

# ✅ Scan endpoint
@app.route("/scan", methods=["POST"])
def scan():
    data = reset_daily_scan_count()

    if data["scan_count"] >= MAX_FREE_SCANS_PER_DAY:
        return jsonify({
            "error": "🛑 Daily free scan limit reached. Please pay to scan more today.",
            "payment_required": True,
            "payment_info": {
                "bank": "Citibank",
                "account": "70588660001898904",
                "swift": "CITIUS33",
                "beneficiary": "Sehan Shahid",
                "email": "sehanshahid8@gmail.com"
            }
        }), 403

    if 'apk' not in request.files:
        return jsonify({"error": "No APK file uploaded"}), 400

    apk = request.files['apk']
    file_path = os.path.join(UPLOAD_DIR, apk.filename)
    apk.save(file_path)

    scan_result = scan_apk(file_path)
    if "error" in scan_result:
        return jsonify(scan_result), 500

    report = generate_report(scan_result)
    data["scan_count"] += 1
    save_scan_data(data)

    return jsonify({
        "report": report,
        "scan_count_today": data["scan_count"]
    })

# ✅ Scan stats
@app.route("/scan-stats", methods=["GET"])
def scan_stats():
    data = reset_daily_scan_count()
    return jsonify({
        "free_scans_remaining": max(0, MAX_FREE_SCANS_PER_DAY - data["scan_count"]),
        "scan_count_today": data["scan_count"],
        "reset_at_midnight": True
    })

# ✅ Home route
@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def home():
    return render_template("index.html")

# ✅ Health check
@app.route("/ping", methods=["GET"])
def ping():
    return "pong"

# ✅ SEO files
@app.route("/robots.txt")
def robots():
    return send_file(os.path.join(app.static_folder, "robots.txt"), mimetype="text/plain")

@app.route("/sitemap.xml")
def sitemap():
    return send_file(os.path.join(app.static_folder, "sitemap.xml"), mimetype="application/xml")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

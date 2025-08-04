from flask import Flask, request, jsonify, send_file, redirect
import os
from scan_worker import scan_apk
from report_generator import generate_report
from datetime import datetime
from replit import db

# 🚫 DO NOT use static_folder="static" to avoid X-Robots-Tag injection
app = Flask(__name__)
UPLOAD_DIR = "/tmp"
MAX_FREE_SCANS_PER_DAY = 300


# ✅ Force HTTPS on all requests
@app.before_request
def enforce_https():
    if request.headers.get("X-Forwarded-Proto", "http") != "https":
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)


# ✅ Auto reset scan count at UTC midnight
def reset_daily_scan_count():
    today = datetime.utcnow().strftime("%Y-%m-%d")
    if db.get("last_reset") != today:
        db["scan_count"] = 0
        db["last_reset"] = today


@app.route("/scan", methods=["POST"])
def scan():
    reset_daily_scan_count()
    count = db.get("scan_count", 0)

    if count >= MAX_FREE_SCANS_PER_DAY:
        return jsonify({
            "error":
            "🛑 Daily free scan limit reached. Please pay to scan more today.",
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
    db["scan_count"] = count + 1
    return jsonify({"report": report, "scan_count_today": db["scan_count"]})


@app.route("/scan-stats", methods=["GET"])
def scan_stats():
    reset_daily_scan_count()
    return jsonify({
        "free_scans_remaining":
        max(0, MAX_FREE_SCANS_PER_DAY - db.get("scan_count", 0)),
        "scan_count_today":
        db.get("scan_count", 0),
        "reset_at_midnight":
        True
    })


# ✅ Serve homepage manually and strip X-Robots-Tag
@app.route("/", methods=["GET"])
def root():
    response = send_file("static/index.html", mimetype="text/html")
    response.headers["Cache-Control"] = "no-store"
    response.headers.pop("X-Robots-Tag", None)
    return response


@app.route("/home", methods=["GET"])
def home():
    response = send_file("static/index.html", mimetype="text/html")
    response.headers["Cache-Control"] = "no-store"
    response.headers.pop("X-Robots-Tag", None)
    return response


# ✅ Manually serve static files (logo, CSS, JS, etc.)
@app.route("/static/<path:filename>")
def serve_static(filename):
    response = send_file(os.path.join("static", filename))
    response.headers["Cache-Control"] = "no-store"
    response.headers.pop("X-Robots-Tag", None)
    return response


@app.route("/ping", methods=["GET"])
def ping():
    return "pong"


@app.route("/robots.txt")
def robots():
    return send_file("static/robots.txt", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    return send_file("static/sitemap.xml", mimetype="application/xml")

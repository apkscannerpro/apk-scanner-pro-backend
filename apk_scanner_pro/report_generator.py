import openai
import os
import smtplib
import textwrap
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import tempfile
import json
import csv

# Import scan functions
from . import scan_worker

# Load OpenAI key
openai.api_key = os.getenv("OPENAI_API_KEY")

# === Bitdefender affiliate link ===
BITDEFENDER_AFFILIATE_LINK = scan_worker.BITDEFENDER_AFFILIATE_LINK

# === Branding constants ===
COMPANY_NAME = "APK Scanner Pro"
COMPANY_URL = "https://apkscannerpro.com"
COMPANY_SUPPORT_EMAIL = "support@apkscannerpro.com"


# === Generate full human-readable report with AI ===
def generate_report(scan_result: dict, premium: bool = False) -> str:
    threat_data = str(scan_result)
    if not premium:
        # Basic report for free scans
        return f"Basic scan report:\nVerdict: {scan_result.get('verdict','Unknown')}\nMalicious: {scan_result.get('virustotal', {}).get('malicious', 0)}\nSuspicious: {scan_result.get('virustotal', {}).get('suspicious', 0)}"
    
    # Premium AI-enhanced report
    prompt = f"""
You are a cybersecurity assistant for {COMPANY_NAME}.
Convert this VirusTotal + AI scan result into a clear, professional,
human-readable malware risk report.

Focus on:
- Risks & Detections
- Security Impact
- Recommendations
- Final Verdict

Scan data:
{threat_data}
"""
    try:
        response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"❌ OpenAI report generation failed: {e}")
        return "Report generation failed. Raw scan data:\n" + threat_data


# === Generate short AI summary ===
def generate_summary(scan_result: dict, premium: bool = False) -> str:
    if not premium:
        return f"Verdict: {scan_result.get('verdict','Unknown')} | Malicious: {scan_result.get('virustotal', {}).get('malicious', 0)} | Suspicious: {scan_result.get('virustotal', {}).get('suspicious', 0)}"
    
    threat_data = str(scan_result)
    prompt = f"""
You are a cybersecurity assistant for {COMPANY_NAME}.
Summarize the scan result in 3-4 lines:
- Is the APK safe or malicious?
- Risk level (Low/Medium/High)
- One clear recommendation

Scan data:
{threat_data}
"""
    try:
        response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"❌ OpenAI summary generation failed: {e}")
        return "Summary unavailable."


# === Generate PDF report ===
def generate_pdf_report(summary: str, report_text: str, file_name: str = "APK File", scan_result: dict = None, premium: bool = True) -> BytesIO:
    if not premium:
        return None  # Free scan → no PDF

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setFont("Helvetica", 11)
    ...
    pdf.save()
    buffer.seek(0)
    return buffer

    y = 770
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, f"{COMPANY_NAME} - Security Report")
    y -= 25

    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, y, f"Scan Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    y -= 15
    pdf.drawString(50, y, f"File: {file_name}")
    y -= 15
    if scan_result and "verdict" in scan_result:
        pdf.drawString(50, y, f"Final Verdict: {scan_result['verdict']}")
        y -= 25

    # Summary
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(50, y, "Summary:")
    y -= 15
    pdf.setFont("Helvetica", 11)
    for line in summary.split("\n"):
        for wrap_line in textwrap.wrap(line, width=90):
            if y < 50:
                pdf.showPage()
                pdf.setFont("Helvetica", 11)
                y = 770
            pdf.drawString(50, y, wrap_line)
            y -= 15

    # Detailed report
    y -= 20
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(50, y, "Detailed Report:")
    y -= 15
    pdf.setFont("Helvetica", 11)
    for line in report_text.split("\n"):
        for wrap_line in textwrap.wrap(line, width=90):
            if y < 50:
                pdf.showPage()
                pdf.setFont("Helvetica", 11)
                y = 770
            pdf.drawString(50, y, wrap_line)
            y -= 15

    # Affiliate footer
    y -= 30
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(50, y, "Protect Your Device:")
    y -= 15
    pdf.setFont("Helvetica-Oblique", 10)
    pdf.drawString(50, y, f"Upgrade your security with Bitdefender 👉 {BITDEFENDER_AFFILIATE_LINK}")

    y -= 30
    pdf.setFont("Helvetica", 9)
    pdf.drawString(50, y, f"Report generated by {COMPANY_NAME} | {COMPANY_URL}")

    pdf.save()
    buffer.seek(0)
    return buffer


# === Append email into subscribers.json + subscribers.csv ===
def add_to_subscribers(email: str, name: str = "", file_name: str = ""):
    try:
        subs_dir = os.path.join(os.path.dirname(__file__), "Subscribers")
        os.makedirs(subs_dir, exist_ok=True)

        # JSON log
        subs_file = os.path.join(subs_dir, "subscribers.json")
        data = []
        if os.path.exists(subs_file):
            try:
                with open(subs_file, "r") as f:
                    data = json.load(f)
            except Exception:
                data = []
        if not any(sub.get("email") == email for sub in data):
            data.append({"name": name, "email": email, "file": file_name})
            with open(subs_file, "w") as f:
                json.dump(data, f, indent=2)

        # CSV log (easy export to Excel/Sheets)
        csv_file = os.path.join(subs_dir, "subscribers.csv")
        write_header = not os.path.exists(csv_file)
        with open(csv_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(["timestamp", "email", "name", "file"])
            writer.writerow([datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), email, name, file_name])

        print(f"📩 Added {email} to subscribers.json & subscribers.csv")

    except Exception as e:
        print(f"❌ Failed to update subscribers: {e}")


# === Send report via email (Plain Text + PDF) ===
def send_report_via_email(to_email: str, scan_result: dict, file_name: str = "APK File", premium: bool = False) -> bool:
    # Generate summary & report based on premium flag
    summary = generate_summary(scan_result, premium=premium)
    report_text = generate_report(scan_result, premium=premium)
    pdf_buffer = generate_pdf_report(summary, report_text, file_name, scan_result, premium=premium) if premium else None

    sender_email = os.getenv("EMAIL_USER")
    sender_pass = os.getenv("EMAIL_PASS")
    smtp_server = os.getenv("SMTP_SERVER", "smtpout.secureserver.net")
    smtp_port = int(os.getenv("SMTP_PORT", 587))

    verdict = scan_result.get("verdict", "Unknown")
    vt_stats = scan_result.get("virustotal", {})
    ai_summary = scan_result.get("ai", {}).get("ai_summary", "")

    msg = MIMEMultipart()
    msg["From"] = f"{COMPANY_NAME} <{sender_email}>"
    msg["To"] = to_email
    msg["Subject"] = f"{COMPANY_NAME} Report – {file_name} ({verdict})"

    # === Branded Plain Text Email Body ===
    plain_body = f"""
🔒 {COMPANY_NAME} – Security Report

📂 File/URL: {file_name}
📅 Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
✅ Verdict: {verdict}

━━━━━━━━━━━━━━━━━━━
📊 Scan Overview
━━━━━━━━━━━━━━━━━━━
- 🔴 Malicious: {vt_stats.get("malicious", 0)}
- 🟠 Suspicious: {vt_stats.get("suspicious", 0)}
- 🟢 Harmless: {vt_stats.get("harmless", 0)}
- ⚪ Undetected: {vt_stats.get("undetected", 0)}

━━━━━━━━━━━━━━━━━━━
📌 Summary
━━━━━━━━━━━━━━━━━━━
{summary}
"""

    # Include AI + detailed report & recommendations only for premium scans
    if premium:
        plain_body += f"""
━━━━━━━━━━━━━━━━━━━
🤖 AI Analysis
━━━━━━━━━━━━━━━━━━━
{ai_summary}

━━━━━━━━━━━━━━━━━━━
📋 Detailed Report
━━━━━━━━━━━━━━━━━━━
{report_text}

━━━━━━━━━━━━━━━━━━━
🛡️ Recommendations
━━━━━━━━━━━━━━━━━━━
1️⃣ Download apps only from trusted sources  
2️⃣ Monitor undetected cases for updates  
3️⃣ Use extra security tools like Bitdefender  
4️⃣ Keep apps updated to patch vulnerabilities  
5️⃣ Backup important data regularly  

━━━━━━━━━━━━━━━━━━━
🔗 Protect your device with Bitdefender:
{BITDEFENDER_AFFILIATE_LINK}
"""

    # Footer always included
    plain_body += f"""

Generated by {COMPANY_NAME}  
🌐 Website: {COMPANY_URL}  
📧 Support: {COMPANY_SUPPORT_EMAIL}
"""

    msg.attach(MIMEText(plain_body, "plain"))

    # Attach PDF only if premium
    if premium and pdf_buffer:
        pdf_attachment = MIMEApplication(pdf_buffer.read(), _subtype="pdf")
        pdf_attachment.add_header("Content-Disposition", "attachment", filename="APK_Scan_Report.pdf")
        msg.attach(pdf_attachment)

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
            server.starttls()
            server.login(sender_email, sender_pass)
            server.sendmail(sender_email, to_email, msg.as_string())

        print(f"✅ Report sent successfully to {to_email}")

        # Save lead
        add_to_subscribers(to_email, "", file_name)

        return True
    except Exception as e:
        print(f"❌ Failed to send report to {to_email}: {e}")
        return False


# === Flask App Endpoint for testing ===
app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan():
    try:
        email = request.form.get("email")
        apk_url = request.form.get("apk_url")
        file = request.files.get("apk")
        premium_flag = request.form.get("premium", "false").lower() == "true"

        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Handle file upload
        if file:
            filename = secure_filename(file.filename)
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                file.save(tmp.name)
                result = scan_worker.scan_apk(tmp.name, premium=premium_flag)
            os.unlink(tmp.name)
            file_name = filename

        # Handle URL scan
        elif apk_url:
            result = scan_worker.scan_url(apk_url, premium=premium_flag)
            file_name = apk_url

        else:
            return jsonify({"error": "No APK file or URL provided"}), 400

        # Send email report (premium or free)
        send_report_via_email(email, result, file_name, premium=premium_flag)

        return jsonify({"status": "success", "result": result, "premium": premium_flag})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


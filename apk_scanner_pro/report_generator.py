import openai
import os
import smtplib
import textwrap
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import tempfile

# Import scan functions
import scan_worker

# Load API key for OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

# === Affiliate placeholder (update later with real link) ===
BITDEFENDER_AFFILIATE_LINK = "https://your-affiliate-link.com"  # 🔑 replace later

# === Generate full human-readable report with OpenAI ===
def generate_report(scan_result: dict) -> str:
    threat_data = str(scan_result)
    prompt = f"""
    You are a cybersecurity assistant for APK Scanner Pro. 
    Convert this VirusTotal scan result into a clear, professional, 
    human-readable malware risk report.

    Focus on:
    - Risks & Detections
    - Security Impact
    - Recommendations
    - Final Verdict

    VirusTotal raw data:
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
def generate_summary(scan_result: dict) -> str:
    threat_data = str(scan_result)
    prompt = f"""
    You are a cybersecurity assistant for APK Scanner Pro.
    Summarize the scan result in 3-4 lines:
    - Is the APK safe or malicious?
    - What is the risk level (Low/Medium/High)?
    - One clear recommendation.

    Raw data:
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
def generate_pdf_report(summary: str, report_text: str) -> BytesIO:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setFont("Helvetica", 11)

    y = 770
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "📄 APK Scanner Pro - Security Report")
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

    pdf.save()
    buffer.seek(0)
    return buffer

# === Send report via email with PDF ===
def send_report_via_email(to_email: str, scan_result: dict, subject="Your APK Scan Report - APK Scanner Pro") -> bool:
    summary = generate_summary(scan_result)
    report_text = generate_report(scan_result)
    pdf_buffer = generate_pdf_report(summary, report_text)

    sender_email = os.getenv("EMAIL_USER")
    sender_pass = os.getenv("EMAIL_PASS")
    smtp_server = os.getenv("SMTP_SERVER", "smtpout.secureserver.net")
    smtp_port = int(os.getenv("SMTP_PORT", 587))

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject

    email_body = f"""
    ✅ APK Scanner Pro - Security Report

    Summary:
    {summary}

    -------------------
    Full Report:
    {report_text}

    -------------------
    🔒 Protect your device with Bitdefender:
    {BITDEFENDER_AFFILIATE_LINK}
    """

    msg.attach(MIMEText(email_body, "plain"))

    pdf_attachment = MIMEApplication(pdf_buffer.read(), _subtype="pdf")
    pdf_attachment.add_header("Content-Disposition", "attachment", filename="APK_Scan_Report.pdf")
    msg.attach(pdf_attachment)

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
            server.starttls()
            server.login(sender_email, sender_pass)
            server.sendmail(sender_email, to_email, msg.as_string())
        print(f"✅ Report sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Failed to send report to {to_email}: {e}")
        return False

# === Flask App ===
app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan():
    try:
        email = request.form.get("email")
        apk_url = request.form.get("apk_url")
        file = request.files.get("apk")

        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Handle file upload
        if file:
            filename = secure_filename(file.filename)
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                file.save(tmp.name)
                result = scan_worker.scan_apk(tmp.name)
            os.unlink(tmp.name)

        # Handle URL scan
        elif apk_url:
            result = scan_worker.scan_url(apk_url)

        else:
            return jsonify({"error": "No APK file or URL provided"}), 400

        # Send email report
        send_report_via_email(email, result)

        return jsonify({"status": "success", "result": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

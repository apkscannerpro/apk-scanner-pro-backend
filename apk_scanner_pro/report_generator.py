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

# Load API key for OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

# === Generate human-readable report with OpenAI ===
def generate_report(scan_result):
    threat_data = str(scan_result)
    prompt = f"""
    You are a cybersecurity assistant for APK Scanner Pro. 
    Convert this VirusTotal scan result into a clear, professional, 
    human-readable malware risk report. 
    Focus on: risks, detections, recommendations, and a final verdict.

    VirusTotal raw data:
    {threat_data}
    """

    response = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


# === Generate PDF report ===
def generate_pdf_report(report_text):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setFont("Helvetica", 11)

    # Wrap text properly
    y = 750
    for line in report_text.split("\n"):
        wrapped_lines = textwrap.wrap(line, width=90)  # 90 chars per line
        for wrap_line in wrapped_lines:
            if y < 50:
                pdf.showPage()
                pdf.setFont("Helvetica", 11)
                y = 750
            pdf.drawString(50, y, wrap_line)
            y -= 15

    pdf.save()
    buffer.seek(0)
    return buffer


# === Send report via email with PDF ===
def send_report_via_email(to_email, scan_result, subject="Your APK Scan Report - APK Scanner Pro"):
    report_text = generate_report(scan_result)
    pdf_buffer = generate_pdf_report(report_text)

    sender_email = os.getenv("EMAIL_USER")      # e.g. support@apkscannerpro.com
    sender_pass = os.getenv("EMAIL_PASS")      # SMTP app password
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject

    # Attach plain text
    msg.attach(MIMEText(report_text, "plain"))

    # Attach PDF
    pdf_attachment = MIMEApplication(pdf_buffer.read(), _subtype="pdf")
    pdf_attachment.add_header("Content-Disposition", "attachment", filename="APK_Scan_Report.pdf")
    msg.attach(pdf_attachment)

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_pass)
            server.sendmail(sender_email, to_email, msg.as_string())
        print(f"✅ Report sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Failed to send report: {e}")
        return False

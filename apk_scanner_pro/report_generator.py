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
def generate_report(scan_result: dict) -> str:
    """
    Convert VirusTotal scan results into a human-readable security report.
    """
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


# === Generate PDF report ===
def generate_pdf_report(report_text: str) -> BytesIO:
    """
    Create a PDF report from the given text.
    """
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setFont("Helvetica", 11)

    y = 750
    for line in report_text.split("\n"):
        wrapped_lines = textwrap.wrap(line, width=90)  # 90 chars per line
        for wrap_line in wrapped_lines:
            if y < 50:  # new page
                pdf.showPage()
                pdf.setFont("Helvetica", 11)
                y = 750
            pdf.drawString(50, y, wrap_line)
            y -= 15

    pdf.save()
    buffer.seek(0)
    return buffer


# === Send report via email with PDF ===
def send_report_via_email(to_email: str, scan_result: dict, subject="Your APK Scan Report - APK Scanner Pro") -> bool:
    """
    Sends the scan report as both plain text and PDF to the user via email.
    """
    report_text = generate_report(scan_result)
    pdf_buffer = generate_pdf_report(report_text)

    sender_email = os.getenv("EMAIL_USER")
    sender_pass = os.getenv("EMAIL_PASS")
    smtp_server = os.getenv("SMTP_SERVER", "smtpout.secureserver.net")
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
        with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
            server.starttls()
            server.login(sender_email, sender_pass)
            server.sendmail(sender_email, to_email, msg.as_string())
        print(f"✅ Report sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Failed to send report to {to_email}: {e}")
        return False

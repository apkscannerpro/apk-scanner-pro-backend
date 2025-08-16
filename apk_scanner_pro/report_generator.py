import openai
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load API key for OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

# === Generate human-readable report with OpenAI ===
def generate_report(scan_result):
    threat_data = str(scan_result)
    prompt = f"""
    You are a cybersecurity assistant. Convert this VirusTotal scan result into a 
    clear, professional, human-readable malware risk report. 
    Focus on risks, detections, recommendations, and final verdict.

    VirusTotal raw data:
    {threat_data}
    """

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response['choices'][0]['message']['content']


# === Send report via email ===
def send_report_via_email(to_email, scan_result, subject="Your APK Scan Report - APK Scanner Pro"):
    report_text = generate_report(scan_result)

    sender_email = os.getenv("EMAIL_USER")      # e.g. support@apkscannerpro.com
    sender_pass = os.getenv("EMAIL_PASS")      # your SMTP/app password
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(report_text, "plain"))

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

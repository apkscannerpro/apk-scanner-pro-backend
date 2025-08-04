import openai
import os

openai.api_key = os.getenv("OPENAI_API_KEY")

def generate_report(scan_result):
    threat_data = str(scan_result)
    prompt = f"Generate a human-readable malware risk report based on this VirusTotal result:\\n{threat_data}"
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response['choices'][0]['message']['content']

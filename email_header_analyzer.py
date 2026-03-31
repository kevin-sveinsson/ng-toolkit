import requests
import re
ABUSEIPDB_KEY = "8f6cdd12345dd540a1e2dbc66ee3c376b1f11221ca87b42878beb7cbc8131c1e2594d8337ca38866"
THRESHOLD = 50
def extract_ip(headers):
    match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})]', headers)
    if match:
        return match.group(1)
    return None

def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    api_headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=api_headers, params=params)
    data = response.json()
    score = data["data"]["abuseConfidenceScore"]
    reports = data["data"]["totalReports"]
    country = data["data"]["countryCode"]
    isp = data["data"]["isp"]
    last_reported = data["data"]["lastReportedAt"]
    print(f"\nIP Address  : {ip}")
    print(f"Abuse Score   : {score}%")
    print(f"Total Reports : {reports}")
    print(f"Country       : {country}")
    print(f"ISP           : {isp}")
    print(f"Last Reported : {last_reported}")
    if score >= THRESHOLD:
        print(f"\n[!] WARNING - High abuse confidence. Treat as malicious.")
    else:
        print(f"\n[CLEAN] Score below threshold. Monitor but likely clean.")

def analyze_headers(raw_headers):
    print("\n=== Email Header Analyzer ===")
    ip = extract_ip(raw_headers)
    if ip:
        print(f"Originating IP found: {ip}")
        check_ip(ip)
    else:
        print("No IP address found in headers.")

raw_headers = """Received: from mail.evil-phish.com [185.220.101.45]
by mail.example.com with SMTP
Subject: Urgent: Verify Your Account
From: security@paypa1.com
To: victim@example.com"""

analyze_headers(raw_headers)
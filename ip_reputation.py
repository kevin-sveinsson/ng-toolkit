import requests
import sys
API_KEY = "8f6cdd12345dd540a1e2dbc66ee3c376b1f11221ca87b42878beb7cbc8131c1e2594d8337ca38866"
def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    print(response.json())
    data = response.json()["data"]
    print(f"\nIP Address    : {data['ipAddress']}")
    print(f"Abuse Score     : {data['abuseConfidenceScore']}%")
    print(f"Total Reports   : {data['totalReports']}")
    print(f"Country         : {data['countryCode']}")
    print(f"ISP             : {data['isp']}")
    print(f"Last Reported   : {data['lastReportedAt']}")
    if data['abuseConfidenceScore'] > 50:
        print("\n[!] WARNING — High abuse confidence. Treat as malicious.")
if __name__ == "__main__":
    check_ip(sys.argv[1])
    
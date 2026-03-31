import requests
API_KEY = "3b87826365a470b704e67c89677005d9c7f31f2274e6b38020045a1fc539043b"
def check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()
    malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    total = data["data"]["attributes"]["last_analysis_stats"]["harmless"] + malicious
    print(f"Hash: {file_hash}")
    print(f"Malicious detections: {malicious} / {total} engines")
    if malicious > 0:
        print(f"VERDICT: MALICIOUS")
    else:
        print(f"VERDICT: CLEAN")

check_hash("44d88612fea8a8f36de82e1278abb02f")
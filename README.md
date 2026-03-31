# NG Toolkit

Python-based security tools engineered from real incident response operations in a 38,000-endpoint PCI-DSS regulated enterprise across 94 network segments.

Each tool was built to solve an actual problem encountered in production — not tutorial exercises.

## Tools

| Tool | Description | MITRE ATT&CK |
|------|-------------|---------------|
| virustotal-hash-enrichment | Automated file hash IOC triage via VirusTotal API | T1204 |
| abuseipdb-ip-reputation | Automated IP reputation analysis via AbuseIPDB API | T1071 |
| phishing-header-analyzer | Email header analysis with auto IP reputation lookup | T1598 |
| arp-spoof-detector | Network-level ARP spoofing and poisoning detection | T1557 |
| lockout-storm-analyzer | Account lockout storm detection and root cause analysis | T1110 |

## Background

Built by a Security Operations professional supporting a 24x7 enterprise environment. Tools are designed for practical SOC workflows — fast triage, automated enrichment, and documented incident response.

## Requirements

Python 3.x — individual requirements listed per tool.

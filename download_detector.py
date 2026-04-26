"""
Unauthorized Software Download Detector

Parses proxy / web filter logs (CSV or Common Log Format), flags downloads of
suspicious file types, enriches the destination domain and IP against
VirusTotal v3 and AbuseIPDB v2, and produces a structured triage report per
flagged event plus an overall summary.

Usage:
    python download_detector.py <path/to/proxy.log>

Environment:
    VT_API_KEY            VirusTotal API v3 key
    ABUSEIPDB_API_KEY     AbuseIPDB API v2 key

The enrichment helpers (`vt_lookup_domain`, `vt_lookup_ip`,
`abuseipdb_lookup_ip`) are intentionally stand-alone so other toolkit scripts
can import and reuse them.
"""

import csv
import ipaddress
import json
import os
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HIGH_RISK_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".ps1", ".vbs", ".dll", ".hta", ".jar",
}
MEDIUM_RISK_EXTENSIONS = {
    ".zip",
}
SUSPICIOUS_EXTENSIONS = HIGH_RISK_EXTENSIONS | MEDIUM_RISK_EXTENSIONS

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

# Free tier safe defaults: VT public = 4 req/min, AbuseIPDB = 1000/day.
VT_MIN_INTERVAL_SEC = 16.0
ABUSEIPDB_MIN_INTERVAL_SEC = 1.5
HTTP_TIMEOUT = 20

MITRE_USER_EXECUTION = {
    "technique_id": "T1204.002",
    "name": "User Execution: Malicious File",
    "rationale": "User-driven download of an executable / scripting payload from the web.",
}
MITRE_PHISHING_LINK = {
    "technique_id": "T1566.002",
    "name": "Phishing: Spearphishing Link",
    "rationale": "Download initiated via a clicked link rather than a direct browse — possible phishing delivery.",
}


# ---------------------------------------------------------------------------
# Caches & rate limiting (shared across the run)
# ---------------------------------------------------------------------------
_vt_domain_cache = {}
_vt_ip_cache = {}
_abuseipdb_cache = {}
_resolution_cache = {}
_last_call_at = {"vt": 0.0, "abuseipdb": 0.0}


def _rate_limit(service, min_interval):
    elapsed = time.monotonic() - _last_call_at[service]
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _last_call_at[service] = time.monotonic()


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------
COMMON_LOG_RE = re.compile(
    r'^(?P<endpoint>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
)

CSV_FIELD_ALIASES = {
    "user": ("user", "username", "userid", "auth_user"),
    "endpoint": ("endpoint", "host", "src_host", "client_host", "client", "src_ip", "ip"),
    "timestamp": ("timestamp", "time", "datetime", "date"),
    "url": ("url", "request_url", "destination_url", "uri"),
}


def _resolve_field(row, names):
    for n in names:
        for key in row:
            if key and key.strip().lower() == n:
                return row[key]
    return None


def parse_log(path):
    """Yield dict entries (user, endpoint, timestamp, url) from a log file.

    Detects CSV vs. Common Log Format by inspecting the first non-empty line.
    Malformed lines are skipped (not raised) so a single bad row doesn't
    abort the run.
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        print(f"[!] Log file not found: {path}")
        sys.exit(1)

    with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        sample = ""
        while not sample:
            line = fh.readline()
            if not line:
                return
            sample = line.strip()
        fh.seek(0)

        is_csv = "," in sample and not sample.startswith(("#", "<"))
        if is_csv:
            yield from _parse_csv(fh)
        else:
            yield from _parse_clf(fh)


def _parse_csv(fh):
    try:
        reader = csv.DictReader(fh)
    except csv.Error as exc:
        print(f"[!] Could not initialise CSV reader: {exc}")
        return
    for raw in reader:
        if not raw:
            continue
        try:
            yield {
                "user": (_resolve_field(raw, CSV_FIELD_ALIASES["user"]) or "").strip() or "unknown",
                "endpoint": (_resolve_field(raw, CSV_FIELD_ALIASES["endpoint"]) or "").strip() or "unknown",
                "timestamp": (_resolve_field(raw, CSV_FIELD_ALIASES["timestamp"]) or "").strip() or "unknown",
                "url": (_resolve_field(raw, CSV_FIELD_ALIASES["url"]) or "").strip(),
                "referer": (raw.get("referer") or raw.get("Referer") or "").strip(),
            }
        except (AttributeError, TypeError):
            continue


def _parse_clf(fh):
    for line in fh:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = COMMON_LOG_RE.match(line)
        if not m:
            continue
        yield {
            "user": m.group("user") if m.group("user") != "-" else "unknown",
            "endpoint": m.group("endpoint"),
            "timestamp": m.group("timestamp"),
            "url": m.group("url"),
            "referer": "",
        }


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def extract_extension(url):
    if not url:
        return None
    try:
        path = urlparse(url).path
    except ValueError:
        return None
    if not path:
        return None
    _, dot, ext = path.rpartition(".")
    if not dot:
        return None
    ext = "." + ext.lower().split("/")[0]
    return ext if ext in SUSPICIOUS_EXTENSIONS else None


def risk_for_extension(ext):
    if ext in HIGH_RISK_EXTENSIONS:
        return "High"
    if ext in MEDIUM_RISK_EXTENSIONS:
        return "Medium"
    return "Low"


def domain_from_url(url):
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def resolve_ip(host):
    """Resolve a hostname to an IPv4/IPv6 address; cache results per run."""
    if not host:
        return None
    if host in _resolution_cache:
        return _resolution_cache[host]
    try:
        ipaddress.ip_address(host)
        _resolution_cache[host] = host
        return host
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(host)
    except (socket.gaierror, socket.herror, OSError):
        ip = None
    _resolution_cache[host] = ip
    return ip


# ---------------------------------------------------------------------------
# Enrichment - reusable across the toolkit
# ---------------------------------------------------------------------------
def vt_lookup_domain(domain, api_key=None):
    if not domain:
        return {"error": "no domain"}
    if domain in _vt_domain_cache:
        return _vt_domain_cache[domain]
    api_key = api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        result = {"error": "VT_API_KEY not set"}
        _vt_domain_cache[domain] = result
        return result

    _rate_limit("vt", VT_MIN_INTERVAL_SEC)
    try:
        resp = requests.get(
            f"{VT_BASE_URL}/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        result = {"error": f"network error: {exc}"}
        _vt_domain_cache[domain] = result
        return result

    if resp.status_code == 404:
        result = {"error": "domain not found in VT"}
    elif resp.status_code != 200:
        result = {"error": f"HTTP {resp.status_code}"}
    else:
        attrs = (resp.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        result = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "detection_ratio": f"{malicious + suspicious}/{total}" if total else "0/0",
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories") or {},
            "malware_family": _extract_malware_family(attrs),
        }
    _vt_domain_cache[domain] = result
    return result


def vt_lookup_ip(ip, api_key=None):
    if not ip:
        return {"error": "no ip"}
    if ip in _vt_ip_cache:
        return _vt_ip_cache[ip]
    api_key = api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        result = {"error": "VT_API_KEY not set"}
        _vt_ip_cache[ip] = result
        return result

    _rate_limit("vt", VT_MIN_INTERVAL_SEC)
    try:
        resp = requests.get(
            f"{VT_BASE_URL}/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        result = {"error": f"network error: {exc}"}
        _vt_ip_cache[ip] = result
        return result

    if resp.status_code == 404:
        result = {"error": "ip not found in VT"}
    elif resp.status_code != 200:
        result = {"error": f"HTTP {resp.status_code}"}
    else:
        attrs = (resp.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        result = {
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total,
            "detection_ratio": f"{malicious + suspicious}/{total}" if total else "0/0",
            "reputation": attrs.get("reputation"),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "malware_family": _extract_malware_family(attrs),
        }
    _vt_ip_cache[ip] = result
    return result


def _extract_malware_family(attrs):
    """VT exposes labels via popular_threat_classification.suggested_threat_label."""
    classification = attrs.get("popular_threat_classification") or {}
    label = classification.get("suggested_threat_label")
    if label:
        return label
    names = classification.get("popular_threat_name") or []
    if names and isinstance(names, list):
        first = names[0]
        if isinstance(first, dict):
            return first.get("value")
        return first
    return None


def abuseipdb_lookup_ip(ip, api_key=None):
    if not ip:
        return {"error": "no ip"}
    if ip in _abuseipdb_cache:
        return _abuseipdb_cache[ip]
    api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        result = {"error": "ABUSEIPDB_API_KEY not set"}
        _abuseipdb_cache[ip] = result
        return result

    _rate_limit("abuseipdb", ABUSEIPDB_MIN_INTERVAL_SEC)
    try:
        resp = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers={"Accept": "application/json", "Key": api_key},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        result = {"error": f"network error: {exc}"}
        _abuseipdb_cache[ip] = result
        return result

    if resp.status_code != 200:
        result = {"error": f"HTTP {resp.status_code}"}
    else:
        data = (resp.json() or {}).get("data") or {}
        reports = data.get("reports") or []
        categories = sorted({c for r in reports for c in (r.get("categories") or [])})
        result = {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "last_reported_at": data.get("lastReportedAt"),
            "reported_categories": categories,
        }
    _abuseipdb_cache[ip] = result
    return result


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
def score_risk(extension, vt_domain, vt_ip, abuse):
    """Combine extension risk with enrichment signals into a final risk band."""
    base = risk_for_extension(extension)

    vt_dom_mal = (vt_domain or {}).get("malicious") or 0
    vt_ip_mal = (vt_ip or {}).get("malicious") or 0
    abuse_score = (abuse or {}).get("abuse_confidence_score") or 0

    if base == "Medium" and (vt_dom_mal >= 3 or vt_ip_mal >= 3 or abuse_score >= 50):
        return "High"
    if base == "High":
        return "High"
    if base == "Medium":
        return "Medium"
    if vt_dom_mal or vt_ip_mal or abuse_score >= 25:
        return "Medium"
    return "Low"


def containment_actions(risk, entry, vt_domain, abuse):
    actions = []
    if risk == "High":
        actions.append(f"Isolate endpoint `{entry['endpoint']}` from the network pending review.")
        actions.append(f"Disable user account `{entry['user']}` until interview / password reset.")
        actions.append(f"Block destination domain `{entry.get('domain') or 'N/A'}` at the proxy/DNS layer.")
        actions.append("Hunt EDR/AV for the downloaded artefact hash and parent process tree.")
    elif risk == "Medium":
        actions.append(f"Sandbox-detonate the file from `{entry.get('domain') or 'N/A'}` before allowing execution.")
        actions.append(f"Notify `{entry['user']}` and confirm the download was business-justified.")
        actions.append("Add the URL to the watchlist for 7 days.")
    else:
        actions.append("Log the event; no immediate containment required.")

    if abuse and (abuse.get("abuse_confidence_score") or 0) >= 75:
        actions.append("Submit destination IP to threat-intel platform for wider blocking.")
    if vt_domain and (vt_domain.get("malicious") or 0) >= 5:
        actions.append("Open an incident ticket — multiple AV engines flag this domain.")
    return actions


def mitre_for_entry(entry):
    techniques = [MITRE_USER_EXECUTION]
    if entry.get("referer"):
        techniques.append(MITRE_PHISHING_LINK)
    return techniques


# ---------------------------------------------------------------------------
# Triage pipeline
# ---------------------------------------------------------------------------
def triage_entry(entry):
    ext = extract_extension(entry.get("url", ""))
    if not ext:
        return None

    domain = domain_from_url(entry["url"])
    ip = resolve_ip(domain)
    entry = dict(entry, domain=domain, ip=ip, extension=ext)

    vt_domain = vt_lookup_domain(domain) if domain else {"error": "no domain"}
    vt_ip = vt_lookup_ip(ip) if ip else {"error": "no ip"}
    abuse = abuseipdb_lookup_ip(ip) if ip else {"error": "no ip"}

    risk = score_risk(ext, vt_domain, vt_ip, abuse)

    return {
        "user": entry["user"],
        "endpoint": entry["endpoint"],
        "timestamp": entry["timestamp"],
        "url": entry["url"],
        "domain": domain,
        "ip": ip,
        "extension": ext,
        "extension_risk": risk_for_extension(ext),
        "risk_level": risk,
        "vt_domain": vt_domain,
        "vt_ip": vt_ip,
        "abuseipdb": abuse,
        "mitre_attack": mitre_for_entry(entry),
        "containment_actions": containment_actions(risk, entry, vt_domain, abuse),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def _fmt(value, default="N/A"):
    if value in (None, "", []):
        return default
    return value


def render_markdown(reports, source_file):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = ["# Unauthorized Software Download Triage Report", ""]
    lines.append(f"- **Source log:** `{source_file}`")
    lines.append(f"- **Generated:** {now}")
    lines.append(f"- **Total flagged downloads:** {len(reports)}")

    high = [r for r in reports if r["risk_level"] == "High"]
    medium = [r for r in reports if r["risk_level"] == "Medium"]
    low = [r for r in reports if r["risk_level"] == "Low"]
    users = sorted({r["user"] for r in reports})

    domain_counts = {}
    for r in reports:
        if r.get("domain"):
            domain_counts[r["domain"]] = domain_counts.get(r["domain"], 0) + 1
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    lines.append(f"- **High / Medium / Low:** {len(high)} / {len(medium)} / {len(low)}")
    lines.append(f"- **Unique users affected:** {len(users)}")
    lines.append("")

    lines.append("## Summary")
    if top_domains:
        lines.append("**Top flagged domains:**")
        for d, c in top_domains:
            lines.append(f"- `{d}` — {c} hit(s)")
    else:
        lines.append("_No domains observed._")
    lines.append("")
    if users:
        lines.append("**Affected users:** " + ", ".join(f"`{u}`" for u in users))
        lines.append("")

    if not reports:
        lines.append("_No suspicious downloads detected._")
        return "\n".join(lines)

    lines.append("## Flagged Downloads")
    for i, r in enumerate(reports, start=1):
        lines.append(f"### {i}. [{r['risk_level']}] {r['user']} @ {r['endpoint']}")
        lines.append(f"- **Timestamp:** {r['timestamp']}")
        lines.append(f"- **File extension:** `{r['extension']}` ({r['extension_risk']}-risk list)")
        lines.append(f"- **URL:** `{r['url']}`")
        lines.append(f"- **Domain / IP:** `{_fmt(r['domain'])}` / `{_fmt(r['ip'])}`")

        vt_d = r["vt_domain"] or {}
        lines.append("- **VirusTotal (domain):** "
                     + (f"_{vt_d['error']}_" if vt_d.get("error")
                        else f"detections {vt_d.get('detection_ratio', 'N/A')}, "
                             f"reputation {_fmt(vt_d.get('reputation'))}, "
                             f"family {_fmt(vt_d.get('malware_family'))}"))
        vt_i = r["vt_ip"] or {}
        lines.append("- **VirusTotal (ip):** "
                     + (f"_{vt_i['error']}_" if vt_i.get("error")
                        else f"detections {vt_i.get('detection_ratio', 'N/A')}, "
                             f"AS {_fmt(vt_i.get('as_owner'))} ({_fmt(vt_i.get('country'))}), "
                             f"family {_fmt(vt_i.get('malware_family'))}"))
        ab = r["abuseipdb"] or {}
        if ab.get("error"):
            lines.append(f"- **AbuseIPDB:** _{ab['error']}_")
        else:
            lines.append(
                f"- **AbuseIPDB:** confidence {_fmt(ab.get('abuse_confidence_score'))}%, "
                f"{_fmt(ab.get('total_reports'))} report(s), "
                f"ISP {_fmt(ab.get('isp'))} ({_fmt(ab.get('country_code'))}), "
                f"categories {_fmt(ab.get('reported_categories'))}"
            )

        lines.append("- **MITRE ATT&CK:**")
        for t in r["mitre_attack"]:
            lines.append(f"  - **{t['technique_id']}** — {t['name']}: {t['rationale']}")

        lines.append("- **Recommended containment:**")
        for action in r["containment_actions"]:
            lines.append(f"  - {action}")
        lines.append("")

    return "\n".join(lines)


def render_terminal(reports):
    if not reports:
        print("[+] No suspicious downloads detected.")
        return
    high = sum(1 for r in reports if r["risk_level"] == "High")
    users = {r["user"] for r in reports}
    print()
    print("=" * 72)
    print(f" Flagged downloads : {len(reports)}")
    print(f" High-risk         : {high}")
    print(f" Unique users      : {len(users)}")
    print("=" * 72)
    for r in reports:
        print(f"[{r['risk_level']:6}] {r['timestamp']}  {r['user']}@{r['endpoint']}  "
              f"{r['extension']}  {r['domain'] or '-'}  ({r['ip'] or '-'})")
    print()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def save_report(markdown, source_file, output_dir="reports"):
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(source_file).stem or "downloads"
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"download_triage_{safe_stem}_{timestamp}.md"
    out_path.write_text(markdown, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print("Usage: python download_detector.py <path/to/proxy.log>")
        sys.exit(0 if argv and argv[0] in ("-h", "--help") else 1)

    log_path = argv[0]
    print(f"[*] Parsing log: {log_path}")

    reports = []
    parsed = skipped = 0
    for entry in parse_log(log_path):
        parsed += 1
        if not entry.get("url"):
            skipped += 1
            continue
        try:
            triage = triage_entry(entry)
        except Exception as exc:
            print(f"[!] Skipped malformed entry ({exc}): {entry}")
            skipped += 1
            continue
        if triage:
            print(f"    flagged: {triage['user']}@{triage['endpoint']} "
                  f"-> {triage['domain']} {triage['extension']} [{triage['risk_level']}]")
            reports.append(triage)

    print(f"[*] Parsed {parsed} entries ({skipped} skipped); {len(reports)} flagged.")

    markdown = render_markdown(reports, log_path)
    out_path = save_report(markdown, log_path)
    render_terminal(reports)
    print(f"[+] Report saved to: {out_path}")


if __name__ == "__main__":
    main()

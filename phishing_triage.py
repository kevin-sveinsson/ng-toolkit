"""
Phishing Email Triage Pipeline

Combines the eml_analyzer CLI with the Anthropic API (Claude Sonnet 4) to
produce a structured triage report from a .eml file.

Usage:
    python phishing_triage.py <path/to/email.eml>

Environment:
    ANTHROPIC_API_KEY    Required - Claude API key.
    ANTHROPIC_MODEL      Optional - override the default model id.

The script is intentionally modular: each step (validation, CLI execution,
LLM analysis, rendering, persistence) is a stand-alone function so the
components can be reused from other tools in the toolkit.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

DEFAULT_MODEL = "claude-sonnet-4-20250514"
EML_ANALYZER_SUBCOMMANDS = ("structure", "header", "text", "html", "attachment", "url")
INSTALL_HINT = (
    "eml_analyzer CLI is not installed.\n"
    "Install it with one of:\n"
    "    pip install eml-analyzer\n"
    "    pipx install eml-analyzer\n"
    "Project page: https://github.com/wahlflo/eml_analyzer"
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def ensure_eml_analyzer_available():
    """Exit cleanly with installation instructions if the CLI is missing."""
    if shutil.which("eml_analyzer") is None:
        print(f"[!] {INSTALL_HINT}")
        sys.exit(2)


def validate_eml_file(path):
    """Return a Path object after sanity-checking the file.

    Raises SystemExit with a friendly message on missing/malformed input so
    callers (the CLI entry point) don't have to duplicate the error handling.
    """
    p = Path(path)
    if not p.exists():
        print(f"[!] File not found: {path}")
        sys.exit(1)
    if not p.is_file():
        print(f"[!] Not a regular file: {path}")
        sys.exit(1)
    if p.stat().st_size == 0:
        print(f"[!] File is empty: {path}")
        sys.exit(1)

    try:
        with p.open("rb") as fh:
            head = fh.read(4096)
    except OSError as exc:
        print(f"[!] Cannot read {path}: {exc}")
        sys.exit(1)

    # A valid RFC 5322 message has at least one header line ("Name: value").
    # We decode loosely because .eml files often contain non-ASCII bytes.
    text = head.decode("utf-8", errors="replace")
    if not re.search(r"(?im)^[A-Za-z\-]+:\s", text):
        print(f"[!] Malformed .eml file (no RFC 5322 headers detected): {path}")
        sys.exit(1)

    return p


# ---------------------------------------------------------------------------
# eml_analyzer execution
# ---------------------------------------------------------------------------
def run_eml_analyzer(eml_path):
    """Run all useful eml_analyzer subcommands and return a combined string."""
    sections = []
    for sub in EML_ANALYZER_SUBCOMMANDS:
        try:
            result = subprocess.run(
                ["eml_analyzer", "--file", str(eml_path), f"--{sub}"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            sections.append(f"=== {sub.upper()} ===\n[timeout running eml_analyzer --{sub}]")
            continue
        except FileNotFoundError:
            # Race: caller normally checks first, but be defensive.
            print(f"[!] {INSTALL_HINT}")
            sys.exit(2)

        body = (result.stdout or "").strip()
        if result.returncode != 0 and result.stderr:
            body = f"{body}\n[stderr]\n{result.stderr.strip()}".strip()
        if not body:
            body = "(no output)"
        sections.append(f"=== {sub.upper()} ===\n{body}")

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Anthropic API call
# ---------------------------------------------------------------------------
TRIAGE_SYSTEM_PROMPT = """You are a senior SOC analyst triaging suspected phishing email reports.
You are given the raw output of the `eml_analyzer` CLI run against a single .eml file.
Produce a precise, evidence-based triage report.

Respond with ONLY a single JSON object - no prose, no markdown fences.
Use this exact schema:

{
  "sender_analysis": {
    "from_address": str,
    "from_domain": str,
    "originating_ip": str | null,
    "reverse_dns": str | null,
    "spoofed": "yes" | "no" | "unknown",
    "spoof_reasoning": str
  },
  "auth_results": {
    "spf": "pass" | "fail" | "softfail" | "neutral" | "none" | "unknown",
    "dkim": "pass" | "fail" | "none" | "unknown",
    "dmarc": "pass" | "fail" | "none" | "unknown",
    "notes": str
  },
  "suspicious_links": [
    {"url": str, "reason": str, "risk": "low" | "medium" | "high"}
  ],
  "attachments": [
    {"filename": str, "md5": str | null, "sha1": str | null, "sha256": str | null, "notes": str}
  ],
  "iocs": {
    "domains": [str],
    "ips": [str],
    "urls": [str],
    "hashes": [str],
    "email_addresses": [str]
  },
  "mitre_attack": [
    {"technique_id": "T1566" | "T1566.001" | "T1566.002" | "T1566.003" | "T1566.004",
     "name": str,
     "rationale": str}
  ],
  "verdict": {
    "label": "Malicious" | "Suspicious" | "Benign",
    "confidence": "low" | "medium" | "high",
    "summary": str
  },
  "containment_actions": [str]
}

Rules:
- Use null or empty arrays when data is missing - never invent values.
- Always include at least the parent T1566 technique when the message is plausibly phishing.
- Keep `containment_actions` actionable (block sender, purge from mailboxes, isolate clicked endpoints, etc.).
"""


def analyze_with_claude(analyzer_output, model=DEFAULT_MODEL, api_key=None):
    """Send the analyzer output to Claude and return the parsed JSON report."""
    try:
        from anthropic import Anthropic
    except ImportError:
        print("[!] The 'anthropic' package is required. Install with: pip install anthropic")
        sys.exit(2)

    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[!] ANTHROPIC_API_KEY environment variable is not set.")
        sys.exit(2)

    client = Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        system=TRIAGE_SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": (
                    "Triage the following eml_analyzer output and return the JSON report:\n\n"
                    f"{analyzer_output}"
                ),
            }
        ],
    )

    raw = "".join(block.text for block in message.content if getattr(block, "type", None) == "text").strip()
    return _parse_json_response(raw)


def _parse_json_response(raw):
    """Tolerate stray prose or accidental code fences around the JSON object."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fenced:
        raw = fenced.group(1)
    else:
        first = raw.find("{")
        last = raw.rfind("}")
        if first != -1 and last != -1 and last > first:
            raw = raw[first : last + 1]
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"[!] Could not parse Claude response as JSON: {exc}")
        print("--- raw response ---")
        print(raw)
        sys.exit(3)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def render_markdown(report, source_file):
    """Convert the structured report dict into a human-readable markdown doc."""
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append("# Phishing Email Triage Report")
    lines.append("")
    lines.append(f"- **Source file:** `{source_file}`")
    lines.append(f"- **Generated:** {now}")
    lines.append("")

    verdict = report.get("verdict", {}) or {}
    lines.append("## Verdict")
    lines.append(f"- **Label:** {verdict.get('label', 'Unknown')}")
    lines.append(f"- **Confidence:** {verdict.get('confidence', 'unknown')}")
    if verdict.get("summary"):
        lines.append(f"- **Summary:** {verdict['summary']}")
    lines.append("")

    sender = report.get("sender_analysis", {}) or {}
    lines.append("## Sender Analysis")
    lines.append(f"- **From:** {sender.get('from_address') or 'N/A'}")
    lines.append(f"- **Domain:** {sender.get('from_domain') or 'N/A'}")
    lines.append(f"- **Originating IP:** {sender.get('originating_ip') or 'N/A'}")
    lines.append(f"- **Reverse DNS:** {sender.get('reverse_dns') or 'N/A'}")
    lines.append(f"- **Spoofed:** {sender.get('spoofed', 'unknown')}")
    if sender.get("spoof_reasoning"):
        lines.append(f"- **Reasoning:** {sender['spoof_reasoning']}")
    lines.append("")

    auth = report.get("auth_results", {}) or {}
    lines.append("## SPF / DKIM / DMARC")
    lines.append(f"- **SPF:** {auth.get('spf', 'unknown')}")
    lines.append(f"- **DKIM:** {auth.get('dkim', 'unknown')}")
    lines.append(f"- **DMARC:** {auth.get('dmarc', 'unknown')}")
    if auth.get("notes"):
        lines.append(f"- **Notes:** {auth['notes']}")
    lines.append("")

    links = report.get("suspicious_links", []) or []
    lines.append("## Suspicious Links")
    if links:
        lines.append("| Risk | URL | Reason |")
        lines.append("|------|-----|--------|")
        for link in links:
            lines.append(
                f"| {link.get('risk', '?')} | `{link.get('url', '')}` | {link.get('reason', '')} |"
            )
    else:
        lines.append("_None identified._")
    lines.append("")

    attachments = report.get("attachments", []) or []
    lines.append("## Attachments")
    if attachments:
        lines.append("| Filename | MD5 | SHA1 | SHA256 | Notes |")
        lines.append("|----------|-----|------|--------|-------|")
        for att in attachments:
            lines.append(
                "| {fn} | {md5} | {sha1} | {sha256} | {notes} |".format(
                    fn=att.get("filename") or "",
                    md5=att.get("md5") or "",
                    sha1=att.get("sha1") or "",
                    sha256=att.get("sha256") or "",
                    notes=att.get("notes") or "",
                )
            )
    else:
        lines.append("_No attachments present._")
    lines.append("")

    iocs = report.get("iocs", {}) or {}
    lines.append("## IOC Summary")
    for label, key in [
        ("Domains", "domains"),
        ("IPs", "ips"),
        ("URLs", "urls"),
        ("Hashes", "hashes"),
        ("Email addresses", "email_addresses"),
    ]:
        values = iocs.get(key) or []
        if values:
            lines.append(f"- **{label}:**")
            for v in values:
                lines.append(f"  - `{v}`")
        else:
            lines.append(f"- **{label}:** _none_")
    lines.append("")

    mitre = report.get("mitre_attack", []) or []
    lines.append("## MITRE ATT&CK Mapping")
    if mitre:
        for tech in mitre:
            lines.append(
                f"- **{tech.get('technique_id', '')}** - {tech.get('name', '')}: "
                f"{tech.get('rationale', '')}"
            )
    else:
        lines.append("_No techniques mapped._")
    lines.append("")

    actions = report.get("containment_actions", []) or []
    lines.append("## Recommended Containment Actions")
    if actions:
        for action in actions:
            lines.append(f"- {action}")
    else:
        lines.append("_None recommended._")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def save_report(markdown, source_file, output_dir="reports"):
    """Write the markdown report to `output_dir` with a timestamped filename."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(source_file).stem or "email"
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"triage_{safe_stem}_{timestamp}.md"
    out_path.write_text(markdown, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print("Usage: python phishing_triage.py <path/to/email.eml>")
        sys.exit(0 if argv and argv[0] in ("-h", "--help") else 1)

    eml_path = validate_eml_file(argv[0])
    ensure_eml_analyzer_available()

    print(f"[*] Running eml_analyzer on {eml_path}")
    analyzer_output = run_eml_analyzer(eml_path)

    model = os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)
    print(f"[*] Sending analyzer output to Claude ({model})")
    report = analyze_with_claude(analyzer_output, model=model)

    markdown = render_markdown(report, str(eml_path))
    out_path = save_report(markdown, str(eml_path))

    print()
    print(markdown)
    print(f"\n[+] Report saved to: {out_path}")


if __name__ == "__main__":
    main()

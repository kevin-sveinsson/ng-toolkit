#!/usr/bin/env python3
"""
arp_spoof_detector.py
ARP Spoofing & Poisoning Detector
Author: NetworkGod
Origin: Built by someone who ran these attacks — now building the detection.

Requirements:
    pip install scapy colorama

Usage:
    sudo python3 arp_spoof_detector.py                  # auto-detect interface
    sudo python3 arp_spoof_detector.py -i eth0          # specify interface
    sudo python3 arp_spoof_detector.py -i eth0 -l arp_alerts.log
    sudo python3 arp_spoof_detector.py --baseline       # build trusted ARP table first
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime

# Third-party
try:
    from scapy.all import ARP, Ether, sniff, get_if_list, conf
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    print("[!] Missing dependencies. Run: pip install scapy colorama")
    sys.exit(1)

colorama_init(autoreset=True)

# ──────────────────────────────────────────────
# CONSTANTS & CONFIG
# ──────────────────────────────────────────────

VERSION = "1.0.0"
TOOL_NAME = "ARP SPOOF DETECTOR"

# How many MAC changes for one IP before we fire an alert
MAC_CHANGE_THRESHOLD = 2

# How many IPs can map to one MAC before we flag it (gateway impersonation)
IP_PER_MAC_THRESHOLD = 3

# Gratuitous ARP burst — how many in how many seconds
GARP_BURST_COUNT = 5
GARP_BURST_WINDOW = 10  # seconds

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
║          {Fore.WHITE}ARP SPOOFING & POISONING DETECTOR{Fore.RED}              ║
║          {Fore.YELLOW}v{VERSION} — Origin: Xbox Live, 2004{Fore.RED}                ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ──────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────

def setup_logger(log_file=None):
    logger = logging.getLogger("arp_detector")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        print(f"{Fore.CYAN}[*] Logging alerts to: {log_file}{Style.RESET_ALL}")

    return logger


# ──────────────────────────────────────────────
# ALERT ENGINE
# ──────────────────────────────────────────────

class AlertEngine:
    """Formats and fires alerts with severity levels."""

    SEVERITIES = {
        "LOW":    Fore.YELLOW,
        "MEDIUM": Fore.MAGENTA,
        "HIGH":   Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }

    def __init__(self, logger):
        self.logger = logger
        self.alert_count = defaultdict(int)

    def fire(self, severity, alert_type, details, packet_info=None):
        color = self.SEVERITIES.get(severity, Fore.WHITE)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.alert_count[severity] += 1

        header = f"{color}[!] {severity} — {alert_type}{Style.RESET_ALL}"
        body   = f"    {Fore.WHITE}{details}{Style.RESET_ALL}"

        print(f"\n{header}")
        print(body)
        if packet_info:
            print(f"    {Fore.CYAN}Packet: {packet_info}{Style.RESET_ALL}")
        print(f"    {Fore.DARKGRAY if hasattr(Fore, 'DARKGRAY') else Fore.WHITE}Timestamp: {timestamp}{Style.RESET_ALL}")

        log_msg = f"[{severity}] {alert_type} | {details}"
        if packet_info:
            log_msg += f" | {packet_info}"
        self.logger.info(log_msg)

    def summary(self):
        print(f"\n{Fore.CYAN}{'─'*55}")
        print(f"  ALERT SUMMARY")
        print(f"{'─'*55}{Style.RESET_ALL}")
        for sev, count in self.alert_count.items():
            color = self.SEVERITIES.get(sev, Fore.WHITE)
            print(f"  {color}{sev:<10}{Style.RESET_ALL} : {count}")
        print(f"{Fore.CYAN}{'─'*55}{Style.RESET_ALL}")


# ──────────────────────────────────────────────
# ARP TABLE — The Core Truth Store
# ──────────────────────────────────────────────

class ARPTable:
    """
    Maintains ground truth of IP → MAC mappings.
    Detects deviations that indicate spoofing/poisoning.
    """

    def __init__(self, alert_engine, logger, baseline_file=None):
        self.alert_engine = alert_engine
        self.logger = logger

        # Primary table: ip -> set of MACs seen
        self.ip_to_macs: dict[str, set] = defaultdict(set)

        # Reverse table: mac -> set of IPs claimed
        self.mac_to_ips: dict[str, set] = defaultdict(set)

        # First-seen MAC per IP (trusted baseline)
        self.trusted: dict[str, str] = {}

        # MAC change history: ip -> list of (old_mac, new_mac, timestamp)
        self.change_history: dict[str, list] = defaultdict(list)

        # Gratuitous ARP tracking: sender_ip -> [timestamps]
        self.garp_timestamps: dict[str, list] = defaultdict(list)

        # Packet counter
        self.total_packets = 0
        self.alert_packets = 0

        # Load baseline if provided
        if baseline_file and os.path.exists(baseline_file):
            self._load_baseline(baseline_file)

    # ── Baseline persistence ──────────────────

    def _load_baseline(self, path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            self.trusted = data.get("trusted", {})
            for ip, mac in self.trusted.items():
                self.ip_to_macs[ip].add(mac)
                self.mac_to_ips[mac].add(ip)
            print(f"{Fore.GREEN}[+] Loaded baseline: {len(self.trusted)} trusted entries from {path}{Style.RESET_ALL}")
        except Exception as e:
            self.logger.warning(f"Failed to load baseline: {e}")

    def save_baseline(self, path="arp_baseline.json"):
        data = {"trusted": self.trusted, "generated": datetime.now().isoformat()}
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"{Fore.GREEN}[+] Baseline saved to {path} ({len(self.trusted)} entries){Style.RESET_ALL}")

    # ── Core Processing ───────────────────────

    def process_packet(self, pkt):
        """Main packet handler — called by Scapy sniff callback."""
        if not pkt.haslayer(ARP):
            return

        self.total_packets += 1
        arp = pkt[ARP]

        op        = arp.op          # 1=who-has (request), 2=is-at (reply)
        sender_ip = arp.psrc        # sender protocol (IP) address
        sender_mac= arp.hwsrc       # sender hardware (MAC) address
        target_ip = arp.pdst        # target IP
        target_mac= arp.hwdst       # target MAC

        # Skip empty/broadcast senders
        if sender_ip in ("0.0.0.0", "") or sender_mac in ("00:00:00:00:00:00", ""):
            return

        packet_summary = (
            f"op={'request' if op==1 else 'reply'} | "
            f"{sender_ip} ({sender_mac}) → {target_ip} ({target_mac})"
        )

        # ── Detection 1: Gratuitous ARP ─────────────────────────────
        # A gratuitous ARP is a reply where sender IP == target IP
        # Legitimate uses: IP conflict detection, failover
        # Malicious use: poisoning caches network-wide
        if op == 2 and sender_ip == target_ip:
            self._check_garp(sender_ip, sender_mac, packet_summary)

        # ── Detection 2: MAC Conflict for Known IP ──────────────────
        if sender_ip in self.trusted:
            trusted_mac = self.trusted[sender_ip]
            if sender_mac != trusted_mac:
                self._flag_mac_conflict(sender_ip, sender_mac, trusted_mac, packet_summary)
        else:
            # First time seeing this IP — establish trust
            self.trusted[sender_ip] = sender_mac
            self.logger.debug(f"[LEARN] {sender_ip} → {sender_mac}")

        # ── Detection 3: One MAC claiming many IPs ──────────────────
        self.mac_to_ips[sender_mac].add(sender_ip)
        if len(self.mac_to_ips[sender_mac]) > IP_PER_MAC_THRESHOLD:
            self._flag_mac_claiming_many_ips(sender_mac, packet_summary)

        # Update tables
        self.ip_to_macs[sender_ip].add(sender_mac)

    # ── Detection Handlers ────────────────────

    def _check_garp(self, sender_ip, sender_mac, pkt_info):
        """
        Gratuitous ARP burst detection.
        Single GARP = possibly legitimate. Burst = poisoning campaign.
        """
        now = time.time()
        timestamps = self.garp_timestamps[sender_ip]

        # Prune old timestamps outside window
        self.garp_timestamps[sender_ip] = [t for t in timestamps if now - t < GARP_BURST_WINDOW]
        self.garp_timestamps[sender_ip].append(now)

        count = len(self.garp_timestamps[sender_ip])

        if count == 1:
            self.alert_engine.fire(
                "LOW",
                "GRATUITOUS ARP DETECTED",
                f"Single unsolicited ARP reply from {sender_ip} ({sender_mac}). "
                f"May be legitimate (HSRP failover, IP conflict probe) — monitor for burst.",
                pkt_info
            )
            self.alert_packets += 1

        elif count >= GARP_BURST_COUNT:
            self.alert_engine.fire(
                "CRITICAL",
                "GRATUITOUS ARP BURST — ACTIVE POISONING",
                f"{count} unsolicited ARP replies from {sender_ip} ({sender_mac}) "
                f"in {GARP_BURST_WINDOW}s. Classic cache poisoning campaign. "
                f"Verify against gateway MAC. Isolate if confirmed.",
                pkt_info
            )
            self.alert_packets += 1
            # Reset burst window to avoid spam
            self.garp_timestamps[sender_ip] = []

    def _flag_mac_conflict(self, ip, new_mac, trusted_mac, pkt_info):
        """
        Core MITM indicator: IP resolving to a different MAC than baseline.
        This is exactly what Cain & Abel was doing — convincing hosts that
        the gateway's IP resolves to the attacker's MAC.
        """
        history = self.change_history[ip]
        history.append({
            "old_mac": trusted_mac,
            "new_mac": new_mac,
            "timestamp": datetime.now().isoformat()
        })

        change_count = len(history)

        severity = "MEDIUM" if change_count < MAC_CHANGE_THRESHOLD else "HIGH"

        self.alert_engine.fire(
            severity,
            "ARP MAC CONFLICT — POTENTIAL SPOOFING",
            f"IP {ip} previously resolved to {trusted_mac} (trusted baseline). "
            f"Now claiming {new_mac}. Change #{change_count}. "
            f"{'ESCALATING — multiple conflicts logged.' if severity == 'HIGH' else 'Monitor for escalation.'}",
            pkt_info
        )
        self.alert_packets += 1

        # Update trusted to new MAC after flagging (prevents alert spam on legitimate changes)
        # Comment this out if you want persistent alerts on every packet from spoofed MAC
        # self.trusted[ip] = new_mac  

    def _flag_mac_claiming_many_ips(self, mac, pkt_info):
        """
        One physical MAC advertising ownership of many IPs.
        Legitimate: HSRP/VRRP virtual routers, badly configured VMs
        Malicious: ARP spoofer intercepting multiple targets simultaneously
        """
        ips = list(self.mac_to_ips[mac])
        self.alert_engine.fire(
            "HIGH",
            "SINGLE MAC CLAIMING MULTIPLE IPs",
            f"MAC {mac} is now associated with {len(ips)} IP addresses: "
            f"{', '.join(ips[:8])}{'...' if len(ips) > 8 else ''}. "
            f"Threshold: {IP_PER_MAC_THRESHOLD}. Verify if HSRP/VRRP is deployed — "
            f"otherwise this is a strong MITM indicator.",
            pkt_info
        )
        self.alert_packets += 1

    # ── Status Display ────────────────────────

    def print_table(self):
        print(f"\n{Fore.CYAN}{'─'*55}")
        print(f"  CURRENT ARP TABLE ({len(self.trusted)} entries)")
        print(f"{'─'*55}")
        print(f"  {'IP Address':<18} {'Trusted MAC':<20} {'All MACs Seen'}")
        print(f"{'─'*55}{Style.RESET_ALL}")
        for ip, mac in sorted(self.trusted.items()):
            all_macs = self.ip_to_macs.get(ip, {mac})
            conflict = len(all_macs) > 1
            color = Fore.RED if conflict else Fore.GREEN
            print(f"  {color}{ip:<18} {mac:<20} {', '.join(all_macs)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*55}{Style.RESET_ALL}")
        print(f"  Packets analyzed : {self.total_packets}")
        print(f"  Alert packets    : {self.alert_packets}")


# ──────────────────────────────────────────────
# INTERFACE UTILS
# ──────────────────────────────────────────────

def list_interfaces():
    print(f"\n{Fore.CYAN}Available interfaces:{Style.RESET_ALL}")
    for iface in get_if_list():
        print(f"  {Fore.WHITE}{iface}{Style.RESET_ALL}")
    print()


def get_default_interface():
    try:
        return conf.iface
    except Exception:
        return None


# ──────────────────────────────────────────────
# BASELINE MODE
# ──────────────────────────────────────────────

def run_baseline_mode(interface, duration=30, output="arp_baseline.json"):
    """
    Passively observe the network for N seconds and build a trusted ARP table.
    Run this before going into detection mode on a known-clean network.
    """
    logger = setup_logger()
    alert_engine = AlertEngine(logger)
    arp_table = ARPTable(alert_engine, logger)

    print(f"{Fore.YELLOW}[BASELINE MODE] Observing ARP traffic for {duration}s on {interface}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Run this on a network you trust to establish ground truth.{Style.RESET_ALL}\n")

    try:
        sniff(
            iface=interface,
            filter="arp",
            prn=arp_table.process_packet,
            timeout=duration,
            store=False
        )
    except Exception as e:
        print(f"{Fore.RED}[!] Sniff error: {e}{Style.RESET_ALL}")
        sys.exit(1)

    arp_table.save_baseline(output)
    arp_table.print_table()


# ──────────────────────────────────────────────
# DETECTION MODE
# ──────────────────────────────────────────────

def run_detection_mode(interface, log_file=None, baseline_file=None):
    logger = setup_logger(log_file)
    alert_engine = AlertEngine(logger)
    arp_table = ARPTable(alert_engine, logger, baseline_file=baseline_file)

    print(f"{Fore.GREEN}[*] Detection active on interface: {Fore.WHITE}{interface}{Style.RESET_ALL}")
    if baseline_file:
        print(f"{Fore.GREEN}[*] Baseline loaded: {baseline_file}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop and view summary{Style.RESET_ALL}\n")

    def graceful_exit(sig, frame):
        print(f"\n{Fore.YELLOW}[*] Stopping capture...{Style.RESET_ALL}")
        arp_table.print_table()
        alert_engine.summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, graceful_exit)

    try:
        sniff(
            iface=interface,
            filter="arp",
            prn=arp_table.process_packet,
            store=False
        )
    except PermissionError:
        print(f"{Fore.RED}[!] Permission denied. Run with sudo.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="ARP Spoofing & Poisoning Detector — NetworkGod",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 arp_spoof_detector.py
  sudo python3 arp_spoof_detector.py -i eth0
  sudo python3 arp_spoof_detector.py -i eth0 -l alerts.log
  sudo python3 arp_spoof_detector.py --baseline -i eth0
  sudo python3 arp_spoof_detector.py -i eth0 --load-baseline arp_baseline.json
  sudo python3 arp_spoof_detector.py --list-interfaces
        """
    )

    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-l", "--log", help="Log file path for alerts")
    parser.add_argument("--baseline", action="store_true", help="Run in baseline collection mode (30s observation)")
    parser.add_argument("--baseline-duration", type=int, default=30, help="Baseline observation duration in seconds")
    parser.add_argument("--baseline-output", default="arp_baseline.json", help="Baseline output file")
    parser.add_argument("--load-baseline", help="Load existing baseline JSON file")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    interface = args.interface or get_default_interface()
    if not interface:
        print(f"{Fore.RED}[!] Could not detect interface. Specify with -i{Style.RESET_ALL}")
        list_interfaces()
        sys.exit(1)

    print(f"{Fore.CYAN}Interface : {interface}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Mode      : {'BASELINE' if args.baseline else 'DETECTION'}{Style.RESET_ALL}\n")

    if args.baseline:
        run_baseline_mode(interface, args.baseline_duration, args.baseline_output)
    else:
        run_detection_mode(interface, log_file=args.log, baseline_file=args.load_baseline)


if __name__ == "__main__":
    main()

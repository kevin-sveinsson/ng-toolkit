#!/usr/bin/env python3
"""
lockout_storm_analyzer.py
Account Lockout Storm Analyzer — Live Windows Event Log Monitor
Author: NetworkGod
Origin: Desert Diamond Casinos IR — stale saved credentials on iPhones/workstations
        hammering ~5 accounts simultaneously. Identified via Event ID 4740 + Cisco ISE.

Requirements:
    pip install colorama pywin32

Usage:
    python lockout_storm_analyzer.py                  # monitor live with defaults
    python lockout_storm_analyzer.py -l alerts.log    # log to file
    python lockout_storm_analyzer.py --poll 15        # poll every 15 seconds
    python lockout_storm_analyzer.py --test           # inject synthetic events for demo

NOTE: Must be run as Administrator to read Security event logs.
      On Domain Controllers you get the richest data.
      On workstations, run against the local Security log.
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    import pywintypes
except ImportError:
    print("[!] Missing pywin32. Run: pip install pywin32")
    print("    Then run: python -m pywin32_postinstall -install")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[!] Missing colorama. Run: pip install colorama")
    sys.exit(1)

# ──────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────

VERSION = "1.0.0"

# Event IDs we care about
EVENT_LOCKOUT         = 4740   # Account locked out — PRIMARY
EVENT_FAILED_LOGON    = 4625   # Failed logon attempt
EVENT_KERB_FAILURE    = 4771   # Kerberos pre-auth failure

# Alert thresholds
SINGLE_ACCOUNT_LOCKOUT_COUNT    = 3    # lockouts on ONE account within window
SINGLE_ACCOUNT_WINDOW_MINUTES  = 5

STORM_ACCOUNT_COUNT             = 5    # unique accounts locked out within window
STORM_WINDOW_MINUTES            = 10

SOURCE_DEVICE_LOCKOUT_COUNT     = 10   # lockouts FROM one device within window
SOURCE_DEVICE_WINDOW_MINUTES    = 5

# How often to poll the event log (seconds)
DEFAULT_POLL_INTERVAL = 10

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║        {Fore.WHITE}ACCOUNT LOCKOUT STORM ANALYZER{Fore.RED}                      ║
║        {Fore.YELLOW}v{VERSION} — IR Origin: Desert Diamond Casinos{Fore.RED}          ║
║        {Fore.CYAN}Events: 4740 | 4625 | 4771{Fore.RED}                          ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────

def setup_logger(log_file=None):
    logger = logging.getLogger("lockout_analyzer")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        print(f"{Fore.CYAN}[*] Logging to: {log_file}{Style.RESET_ALL}")

    return logger


# ──────────────────────────────────────────────
# ALERT ENGINE
# ──────────────────────────────────────────────

class AlertEngine:
    SEVERITIES = {
        "INFO":     Fore.CYAN,
        "LOW":      Fore.YELLOW,
        "MEDIUM":   Fore.MAGENTA,
        "HIGH":     Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }

    def __init__(self, logger):
        self.logger = logger
        self.alert_count = defaultdict(int)
        self._lock = Lock()

    def fire(self, severity, alert_type, details, context=None):
        with self._lock:
            color = self.SEVERITIES.get(severity, Fore.WHITE)
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.alert_count[severity] += 1

            print(f"\n{color}{'═'*60}")
            print(f"  [{severity}] {alert_type}")
            print(f"{'═'*60}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}{details}{Style.RESET_ALL}")
            if context:
                for k, v in context.items():
                    print(f"  {Fore.CYAN}{k:<20}{Style.RESET_ALL}: {v}")
            print(f"  {Fore.YELLOW}Timestamp{Style.RESET_ALL}            : {timestamp}")

            log_msg = f"[{severity}] {alert_type} | {details}"
            if context:
                log_msg += " | " + " | ".join(f"{k}={v}" for k, v in context.items())
            self.logger.info(log_msg)

    def summary(self):
        print(f"\n{Fore.CYAN}{'─'*55}")
        print(f"  ALERT SUMMARY")
        print(f"{'─'*55}{Style.RESET_ALL}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self.alert_count.get(sev, 0)
            if count > 0:
                color = self.SEVERITIES.get(sev, Fore.WHITE)
                print(f"  {color}{sev:<12}{Style.RESET_ALL} : {count}")
        if not any(self.alert_count.values()):
            print(f"  {Fore.GREEN}No alerts fired.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*55}{Style.RESET_ALL}")


# ──────────────────────────────────────────────
# EVENT PARSER
# ──────────────────────────────────────────────

class LockoutEvent:
    """Normalized representation of a lockout-related event."""

    def __init__(self, event_id, timestamp, account_name, domain,
                 caller_computer, caller_ip, logon_type, raw_message):
        self.event_id        = event_id
        self.timestamp       = timestamp
        self.account_name    = account_name.lower() if account_name else "unknown"
        self.domain          = domain or ""
        self.caller_computer = caller_computer or "UNKNOWN"
        self.caller_ip       = caller_ip or "N/A"
        self.logon_type      = logon_type or "N/A"
        self.raw_message     = raw_message

    def __repr__(self):
        return (f"LockoutEvent(id={self.event_id}, account={self.account_name}, "
                f"source={self.caller_computer}, time={self.timestamp})")


def parse_event(event):
    """
    Extract structured fields from a raw win32evtlog event record.
    Event ID 4740 fields:
        0 = TargetUserName
        1 = TargetDomainName
        4 = CallerComputerName
    Event ID 4625 fields:
        5  = TargetUserName
        6  = TargetDomainName
        10 = LogonType
        19 = WorkstationName
        20 = IpAddress
    Event ID 4771 fields:
        0 = TargetUserName
        7 = IpAddress
    """
    try:
        event_id = event.EventID & 0xFFFF
        timestamp = event.TimeGenerated.Format()

        strings = event.StringInserts or []

        account_name    = ""
        domain          = ""
        caller_computer = ""
        caller_ip       = ""
        logon_type      = ""

        if event_id == EVENT_LOCKOUT:
            account_name    = strings[0] if len(strings) > 0 else ""
            domain          = strings[1] if len(strings) > 1 else ""
            caller_computer = strings[4] if len(strings) > 4 else ""

        elif event_id == EVENT_FAILED_LOGON:
            account_name    = strings[5]  if len(strings) > 5  else ""
            domain          = strings[6]  if len(strings) > 6  else ""
            logon_type      = strings[10] if len(strings) > 10 else ""
            caller_computer = strings[13] if len(strings) > 13 else ""
            caller_ip       = strings[19] if len(strings) > 19 else ""

        elif event_id == EVENT_KERB_FAILURE:
            account_name = strings[0] if len(strings) > 0 else ""
            caller_ip    = strings[6] if len(strings) > 6 else ""

        raw_message = str(strings)

        return LockoutEvent(
            event_id=event_id,
            timestamp=timestamp,
            account_name=account_name,
            domain=domain,
            caller_computer=caller_computer,
            caller_ip=caller_ip,
            logon_type=logon_type,
            raw_message=raw_message
        )

    except Exception:
        return None


# ──────────────────────────────────────────────
# CORRELATION ENGINE
# ──────────────────────────────────────────────

class CorrelationEngine:
    """
    Correlates lockout events across three detection axes:
    1. Single account lockout frequency
    2. Storm detection — multiple accounts locked simultaneously
    3. Source device correlation — one machine hammering multiple accounts
       (the stale credential pattern from the Desert Diamond IR)
    """

    def __init__(self, alert_engine, logger):
        self.alert_engine = alert_engine
        self.logger = logger
        self._lock = Lock()

        # account -> [timestamps of lockout events]
        self.account_lockouts: dict[str, list] = defaultdict(list)

        # source_device -> [LockoutEvent]
        self.device_lockouts: dict[str, list] = defaultdict(list)

        # Fired alert dedup: track what we've already alerted on
        self.fired_alerts: set = set()

        # Stats
        self.total_events     = 0
        self.lockout_events   = 0
        self.failed_logons    = 0
        self.kerb_failures    = 0

    def _prune(self, timestamps, window_minutes):
        """Remove timestamps outside the detection window."""
        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        return [t for t in timestamps if t > cutoff]

    def _prune_events(self, events, window_minutes):
        """Remove events outside the detection window."""
        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        return [e for e in events if self._parse_ts(e.timestamp) > cutoff]

    def _parse_ts(self, ts_string):
        """Parse win32 timestamp string to datetime."""
        try:
            return datetime.strptime(ts_string, "%m/%d/%y %H:%M:%S")
        except Exception:
            return datetime.now()

    def process(self, event: LockoutEvent):
        """Main processing entry point for each parsed event."""
        with self._lock:
            self.total_events += 1

            if event.event_id == EVENT_LOCKOUT:
                self.lockout_events += 1
                self._process_lockout(event)

            elif event.event_id == EVENT_FAILED_LOGON:
                self.failed_logons += 1
                self._process_failed_logon(event)

            elif event.event_id == EVENT_KERB_FAILURE:
                self.kerb_failures += 1
                self._log_kerb(event)

    # ── Detection 1: Single Account Lockout Frequency ─────────────

    def _process_lockout(self, event: LockoutEvent):
        now = datetime.now()
        account = event.account_name
        device  = event.caller_computer.upper().strip("$") or "UNKNOWN"

        # Log the raw event
        self.logger.debug(
            f"[4740] LOCKOUT | Account: {account} | "
            f"Source: {device} | Time: {event.timestamp}"
        )

        print(
            f"{Fore.YELLOW}[4740]{Style.RESET_ALL} "
            f"Lockout — {Fore.WHITE}{account}{Style.RESET_ALL} "
            f"from {Fore.CYAN}{device}{Style.RESET_ALL} "
            f"at {event.timestamp}"
        )

        # Track per-account
        self.account_lockouts[account].append(now)
        self.account_lockouts[account] = self._prune(
            self.account_lockouts[account],
            SINGLE_ACCOUNT_WINDOW_MINUTES
        )

        # Track per-device
        self.device_lockouts[device].append(event)
        self.device_lockouts[device] = self._prune_events(
            self.device_lockouts[device],
            SOURCE_DEVICE_WINDOW_MINUTES
        )

        # ── Check: single account threshold
        count = len(self.account_lockouts[account])
        if count >= SINGLE_ACCOUNT_LOCKOUT_COUNT:
            alert_key = f"single_account_{account}_{count}"
            if alert_key not in self.fired_alerts:
                self.fired_alerts.add(alert_key)
                self.alert_engine.fire(
                    "MEDIUM",
                    "REPEATED ACCOUNT LOCKOUT",
                    f"Account '{account}' has been locked out {count}x "
                    f"in {SINGLE_ACCOUNT_WINDOW_MINUTES} minutes.",
                    context={
                        "Account"        : account,
                        "Lockout Count"  : count,
                        "Window"         : f"{SINGLE_ACCOUNT_WINDOW_MINUTES} min",
                        "Source Device"  : device,
                        "MITRE ATT&CK"   : "T1110.001 — Password Guessing",
                        "Recommendation" : "Check for stale saved credentials on source device"
                    }
                )

        # ── Check: storm threshold — unique accounts locked in window
        self._check_storm()

        # ── Check: source device hammering multiple accounts (THE IR STORY)
        self._check_source_device(device)

    # ── Detection 2: Lockout Storm ────────────────────────────────

    def _check_storm(self):
        """
        Count unique accounts with at least one lockout in the storm window.
        This is the macro-level signal — many accounts going down simultaneously.
        """
        storm_window = datetime.now() - timedelta(minutes=STORM_WINDOW_MINUTES)
        active_accounts = [
            acct for acct, timestamps in self.account_lockouts.items()
            if any(t > storm_window for t in timestamps)
        ]

        count = len(active_accounts)
        if count >= STORM_ACCOUNT_COUNT:
            alert_key = f"storm_{count}_{','.join(sorted(active_accounts))}"
            if alert_key not in self.fired_alerts:
                self.fired_alerts.add(alert_key)

                # Find the dominant source device
                all_recent_events = []
                for events in self.device_lockouts.values():
                    all_recent_events.extend(events)

                device_counts = defaultdict(int)
                for e in all_recent_events:
                    device_counts[e.caller_computer.upper()] += 1

                top_device = max(device_counts, key=device_counts.get) if device_counts else "UNKNOWN"

                self.alert_engine.fire(
                    "HIGH",
                    "ACCOUNT LOCKOUT STORM DETECTED",
                    f"{count} unique accounts locked out within {STORM_WINDOW_MINUTES} minutes. "
                    f"This pattern is consistent with a stale credential broadcast storm.",
                    context={
                        "Affected Accounts" : ", ".join(active_accounts[:8]) + ("..." if count > 8 else ""),
                        "Account Count"     : count,
                        "Storm Window"      : f"{STORM_WINDOW_MINUTES} min",
                        "Dominant Source"   : top_device,
                        "MITRE ATT&CK"      : "T1110 — Brute Force / Credential Stuffing",
                        "Recommendation"    : (
                            "1. Identify source device(s) via Cisco ISE or DHCP logs. "
                            "2. Check for stale saved credentials (mobile devices, workstations). "
                            "3. Force password reset on affected accounts after source is isolated."
                        )
                    }
                )

    # ── Detection 3: Source Device — Stale Credential Bomb ────────

    def _check_source_device(self, device: str):
        """
        One device generating lockouts across multiple accounts.
        This is THE signature pattern from the Desert Diamond IR —
        iPhones and workstations with stale saved credentials hammering
        multiple accounts simultaneously after a password change.
        """
        if device == "UNKNOWN":
            return

        recent_events = self.device_lockouts.get(device, [])
        total_lockouts = len(recent_events)

        if total_lockouts < SOURCE_DEVICE_LOCKOUT_COUNT:
            return

        # Unique accounts this device has locked out
        unique_accounts = list({e.account_name for e in recent_events})
        acct_count = len(unique_accounts)

        alert_key = f"source_device_{device}_{total_lockouts}"
        if alert_key not in self.fired_alerts:
            self.fired_alerts.add(alert_key)

            severity = "CRITICAL" if acct_count >= 3 else "HIGH"

            self.alert_engine.fire(
                severity,
                "STALE CREDENTIAL BOMB — SINGLE SOURCE MULTI-ACCOUNT LOCKOUT",
                f"Device '{device}' has generated {total_lockouts} lockout events "
                f"across {acct_count} unique account(s) in {SOURCE_DEVICE_WINDOW_MINUTES} minutes. "
                f"Classic stale saved credential pattern.",
                context={
                    "Source Device"     : device,
                    "Total Lockouts"    : total_lockouts,
                    "Unique Accounts"   : ", ".join(unique_accounts[:6]) + ("..." if acct_count > 6 else ""),
                    "Account Count"     : acct_count,
                    "Window"            : f"{SOURCE_DEVICE_WINDOW_MINUTES} min",
                    "MITRE ATT&CK"      : "T1110.001 — Password Guessing (Credential Stuffing)",
                    "Root Cause"        : "Likely stale saved credentials on mobile device or workstation",
                    "Recommendation"    : (
                        "1. Isolate or locate device via Cisco ISE MAC lookup. "
                        "2. Clear saved credentials on device. "
                        "3. Unlock affected accounts after device is remediated. "
                        "4. Force MFA re-enrollment if applicable."
                    )
                }
            )

    # ── Detection 4: Failed Logon Logging ─────────────────────────

    def _process_failed_logon(self, event: LockoutEvent):
        self.logger.debug(
            f"[4625] FAILED LOGON | Account: {event.account_name} | "
            f"Source: {event.caller_computer} | IP: {event.caller_ip} | "
            f"Logon Type: {event.logon_type}"
        )
        print(
            f"{Fore.MAGENTA}[4625]{Style.RESET_ALL} "
            f"Failed logon — {Fore.WHITE}{event.account_name}{Style.RESET_ALL} "
            f"from {Fore.CYAN}{event.caller_computer}{Style.RESET_ALL} "
            f"({event.caller_ip}) at {event.timestamp}"
        )

    def _log_kerb(self, event: LockoutEvent):
        self.logger.debug(
            f"[4771] KERBEROS FAILURE | Account: {event.account_name} | "
            f"IP: {event.caller_ip}"
        )
        print(
            f"{Fore.BLUE}[4771]{Style.RESET_ALL} "
            f"Kerberos failure — {Fore.WHITE}{event.account_name}{Style.RESET_ALL} "
            f"from {Fore.CYAN}{event.caller_ip}{Style.RESET_ALL} "
            f"at {event.timestamp}"
        )

    # ── Status ────────────────────────────────────────────────────

    def print_stats(self):
        print(f"\n{Fore.CYAN}{'─'*55}")
        print(f"  EVENT STATISTICS")
        print(f"{'─'*55}{Style.RESET_ALL}")
        print(f"  Total events processed : {self.total_events}")
        print(f"  Lockout events (4740)  : {self.lockout_events}")
        print(f"  Failed logons  (4625)  : {self.failed_logons}")
        print(f"  Kerberos fails (4771)  : {self.kerb_failures}")
        print(f"\n  {Fore.WHITE}AFFECTED ACCOUNTS{Style.RESET_ALL}")
        for acct, timestamps in sorted(self.account_lockouts.items()):
            print(f"  {Fore.YELLOW}{acct:<30}{Style.RESET_ALL} {len(timestamps)} lockout(s)")
        print(f"\n  {Fore.WHITE}SOURCE DEVICES{Style.RESET_ALL}")
        for device, events in sorted(self.device_lockouts.items()):
            unique_accts = {e.account_name for e in events}
            print(f"  {Fore.CYAN}{device:<30}{Style.RESET_ALL} {len(events)} events | {len(unique_accts)} account(s)")
        print(f"{Fore.CYAN}{'─'*55}{Style.RESET_ALL}")


# ──────────────────────────────────────────────
# EVENT LOG READER
# ──────────────────────────────────────────────

class EventLogMonitor:
    """
    Polls the Windows Security event log for new events.
    Tracks record number to avoid reprocessing.
    """

    TARGET_EVENT_IDS = {EVENT_LOCKOUT, EVENT_FAILED_LOGON, EVENT_KERB_FAILURE}

    def __init__(self, server="localhost", log_name="Security",
                 correlation_engine=None, logger=None, poll_interval=DEFAULT_POLL_INTERVAL):
        self.server            = server
        self.log_name          = log_name
        self.correlation       = correlation_engine
        self.logger            = logger
        self.poll_interval     = poll_interval
        self.last_record_num   = None
        self.running           = False

    def _get_last_record(self, handle):
        """Get the most recent record number to establish our starting position."""
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if events:
                return events[0].RecordNumber
        except Exception:
            pass
        return 0

    def _read_new_events(self, handle):
        """Read events newer than our last known record number."""
        new_events = []
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        try:
            while True:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                for event in events:
                    if self.last_record_num and event.RecordNumber <= self.last_record_num:
                        continue
                    event_id = event.EventID & 0xFFFF
                    if event_id in self.TARGET_EVENT_IDS:
                        new_events.append(event)
                if events:
                    self.last_record_num = events[-1].RecordNumber
        except pywintypes.error as e:
            if e.winerror != 38:  # 38 = no more data, expected
                self.logger.warning(f"Event log read error: {e}")

        return new_events

    def start(self):
        """Main polling loop."""
        self.running = True
        print(f"{Fore.GREEN}[*] Connecting to event log: {self.server}\\{self.log_name}{Style.RESET_ALL}")

        try:
            handle = win32evtlog.OpenEventLog(self.server, self.log_name)
        except pywintypes.error as e:
            print(f"{Fore.RED}[!] Cannot open event log: {e}")
            print(f"    Make sure you are running as Administrator.{Style.RESET_ALL}")
            sys.exit(1)

        # Establish starting position — don't replay history
        self.last_record_num = self._get_last_record(handle)
        print(f"{Fore.GREEN}[*] Starting from record #{self.last_record_num}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Polling every {self.poll_interval}s — Press Ctrl+C to stop{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}Watching for Event IDs: 4740 (Lockout) | 4625 (Failed Logon) | 4771 (Kerberos){Style.RESET_ALL}\n")

        while self.running:
            try:
                new_events = self._read_new_events(handle)
                for raw_event in new_events:
                    parsed = parse_event(raw_event)
                    if parsed:
                        self.correlation.process(parsed)

                time.sleep(self.poll_interval)

            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Poll error: {e}")
                time.sleep(self.poll_interval)

        win32evtlog.CloseEventLog(handle)
        self.running = False

    def stop(self):
        self.running = False


# ──────────────────────────────────────────────
# TEST MODE — Synthetic Event Injection
# ──────────────────────────────────────────────

def run_test_mode(correlation_engine, logger):
    """
    Injects synthetic events to demonstrate detection logic.
    Simulates the Desert Diamond stale credential storm scenario.
    """
    print(f"{Fore.YELLOW}[TEST MODE] Injecting synthetic events — simulating stale credential storm...{Style.RESET_ALL}\n")
    time.sleep(1)

    def make_event(event_id, account, device, ip="192.168.1.50", logon_type="3"):
        return LockoutEvent(
            event_id=event_id,
            timestamp=datetime.now().strftime("%m/%d/%y %H:%M:%S"),
            account_name=account,
            domain="CORP",
            caller_computer=device,
            caller_ip=ip,
            logon_type=logon_type,
            raw_message="[synthetic test event]"
        )

    scenarios = [
        # Single account repeated lockout
        ("Scenario 1: Single account repeated lockout (MEDIUM)", [
            make_event(EVENT_LOCKOUT, "jsmith", "IPHONE-JSMITH"),
            make_event(EVENT_LOCKOUT, "jsmith", "IPHONE-JSMITH"),
            make_event(EVENT_LOCKOUT, "jsmith", "IPHONE-JSMITH"),
        ]),
        # Stale credential bomb from one device
        ("Scenario 2: Stale credential bomb — one device, multiple accounts (CRITICAL)", [
            make_event(EVENT_LOCKOUT, "jsmith",    "WS-ACCOUNTING-04"),
            make_event(EVENT_LOCKOUT, "mrodriguez", "WS-ACCOUNTING-04"),
            make_event(EVENT_LOCKOUT, "twilliams", "WS-ACCOUNTING-04"),
            make_event(EVENT_LOCKOUT, "kpatel",    "WS-ACCOUNTING-04"),
            make_event(EVENT_LOCKOUT, "bthompson",  "WS-ACCOUNTING-04"),
            make_event(EVENT_FAILED_LOGON, "jsmith", "WS-ACCOUNTING-04", logon_type="3"),
            make_event(EVENT_LOCKOUT, "jsmith",    "WS-ACCOUNTING-04"),
            make_event(EVENT_LOCKOUT, "mrodriguez", "WS-ACCOUNTING-04"),
            make_event(EVENT_LOCKOUT, "twilliams", "WS-ACCOUNTING-04"),
            make_event(EVENT_LOCKOUT, "kpatel",    "WS-ACCOUNTING-04"),
        ]),
        # Storm — multiple devices, multiple accounts
        ("Scenario 3: Lockout storm — multiple sources (HIGH)", [
            make_event(EVENT_LOCKOUT, "agarcia",   "IPHONE-AGARCIA",  ip="10.0.0.23"),
            make_event(EVENT_LOCKOUT, "djohnson",  "IPHONE-DJOHNSON", ip="10.0.0.24"),
            make_event(EVENT_LOCKOUT, "rlee",      "IPHONE-RLEE",     ip="10.0.0.25"),
            make_event(EVENT_LOCKOUT, "cmartinez", "LAPTOP-CMARTINEZ",ip="10.0.0.26"),
            make_event(EVENT_LOCKOUT, "nwilson",   "LAPTOP-NWILSON",  ip="10.0.0.27"),
            make_event(EVENT_KERB_FAILURE, "agarcia", "IPHONE-AGARCIA", ip="10.0.0.23"),
        ]),
    ]

    for title, events in scenarios:
        print(f"\n{Fore.CYAN}{'─'*55}")
        print(f"  {title}")
        print(f"{'─'*55}{Style.RESET_ALL}")
        for event in events:
            correlation_engine.process(event)
            time.sleep(0.3)
        time.sleep(1)

    print(f"\n{Fore.GREEN}[TEST MODE COMPLETE]{Style.RESET_ALL}")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Account Lockout Storm Analyzer — NetworkGod",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python lockout_storm_analyzer.py
  python lockout_storm_analyzer.py -l alerts.log
  python lockout_storm_analyzer.py --poll 15
  python lockout_storm_analyzer.py --test
  python lockout_storm_analyzer.py --server DC01
        """
    )
    parser.add_argument("-l", "--log",    help="Alert log file path")
    parser.add_argument("--poll",         type=int, default=DEFAULT_POLL_INTERVAL,
                        help=f"Poll interval in seconds (default: {DEFAULT_POLL_INTERVAL})")
    parser.add_argument("--server",       default="localhost",
                        help="Remote server to monitor (default: localhost)")
    parser.add_argument("--test",         action="store_true",
                        help="Run in test mode with synthetic events (no admin required)")

    args = parser.parse_args()

    logger       = setup_logger(args.log)
    alert_engine = AlertEngine(logger)
    correlation  = CorrelationEngine(alert_engine, logger)

    def graceful_exit(sig, frame):
        print(f"\n{Fore.YELLOW}[*] Shutting down...{Style.RESET_ALL}")
        correlation.print_stats()
        alert_engine.summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, graceful_exit)

    print(f"{Fore.CYAN}Thresholds{Style.RESET_ALL}")
    print(f"  Single account lockouts : {SINGLE_ACCOUNT_LOCKOUT_COUNT} in {SINGLE_ACCOUNT_WINDOW_MINUTES} min → MEDIUM")
    print(f"  Storm threshold         : {STORM_ACCOUNT_COUNT} accounts in {STORM_WINDOW_MINUTES} min → HIGH")
    print(f"  Source device bomb      : {SOURCE_DEVICE_LOCKOUT_COUNT} lockouts in {SOURCE_DEVICE_WINDOW_MINUTES} min → CRITICAL\n")

    if args.test:
        run_test_mode(correlation, logger)
        correlation.print_stats()
        alert_engine.summary()
        return

    monitor = EventLogMonitor(
        server=args.server,
        log_name="Security",
        correlation_engine=correlation,
        logger=logger,
        poll_interval=args.poll
    )

    try:
        monitor.start()
    except KeyboardInterrupt:
        pass
    finally:
        correlation.print_stats()
        alert_engine.summary()


if __name__ == "__main__":
    main()

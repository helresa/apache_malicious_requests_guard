#!/usr/bin/env python3
"""
Apache Malicious Requests Guard
--------------------------------
Tail one or more Apache access logs (file or directory), detect likely-malicious requests
(SQLi, XSS, path traversal, WordPress probes, env file grabs, phpMyAdmin scans, etc.).
When an IP exceeds a configurable threshold within a rolling time window, execute a
system command to block it (e.g., iptables/ufw/firewall-cmd).

Compatible with Python 3.5+ (no capture_output).

Examples
--------
# Dry run from start of file, block after 10 hits in 5 minutes
python3 apache-malicious-requests-guard.py \
  --log /var/log/apache2/access.log \
  --threshold 10 --window 300 --from-start --dry-run

# Tail all logs in a directory (e.g. cPanel domlogs)
python3 apache-malicious-requests-guard.py \
  --log /var/log/apache2/domlogs \
  --threshold 15 --window 300
"""
import argparse
import ipaddress
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Iterable, Optional, Pattern
from urllib.parse import unquote_plus

# -----------------------------
# Log parsing
# -----------------------------
LOG_RE: Pattern[str] = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+\"(?P<method>[A-Z]+)\s+(?P<path>[^\s\"]+)\s+(?P<proto>HTTP/[^\"]+)\"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\""
)

APACHE_TIME_RE: Pattern[str] = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})")
MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

def parse_apache_time(s: str) -> datetime:
    m = APACHE_TIME_RE.match(s)
    if not m:
        return datetime.now(timezone.utc)
    day, mon, year, hh, mm, ss, offset = m.groups()
    tz_sign = 1 if offset.startswith('+') else -1
    tz_hours = int(offset[1:3])
    tz_mins = int(offset[3:5])
    tz = timezone(timedelta(hours=tz_hours * tz_sign, minutes=tz_mins * tz_sign))
    return datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=tz)

# -----------------------------
# Malicious heuristics
# -----------------------------
DEFAULT_PATTERNS = [
    r"(?i)(union\s+select|sleep\s*\(|benchmark\s*\(|information_schema|load_file\s*\(|or\s+1=1)",
    r"(?i)(<script|%3cscript|onerror=|onload=|javascript:)",
    r"(?i)(\.(env|git|svn)|/\.env|/\.git|/wp-config.php|/composer\.json)",
    r"(?i)(/phpmyadmin|/pma|/mysqladmin|/adminer\.php)",
    r"(?i)(\.\./|%2e%2e/|%252e%252e/)",
    r"(?i)(/wp-login\.php|/xmlrpc\.php|/wp-json|/wp-admin)",
    r"(?i)(/\.vscode/|/id_rsa|/\.ssh/|/keys?\.txt)",
    r"(?i)(/\.DS_Store|/server-status|/owa|/actuator|/jmx)",
    r"(?i)(select\s+.*from\s+|insert\s+into\s+|update\s+\w+\s+set)"
]

SUSPICIOUS_UA = [r"(?i)(sqlmap|nikto|nmap|acunetix|nessus|dirbuster|curl/|python-requests|Go-http-client)"]
SUSPICIOUS_STATUS = {401, 403, 404, 405, 408, 418, 429, 500, 501, 502, 503}

FORBIDDEN_PATHS = [
    r"^/wordpress/?",
    r"^/wp/?",
    r"^/new/?",
    r"^/old/?",
    r"^/test/?",
    r"^/backup/?",
    r"^/bk/?",
    r"^/private/?",
    r"^/tmp/?",
    r"^/etc/",
    r"^/root/",
    r"^/proc/",
]
FORBIDDEN_REGEX = [re.compile(p, re.IGNORECASE) for p in FORBIDDEN_PATHS]

# -----------------------------
# Core detector
# -----------------------------
class Detector:
    def __init__(self, threshold: int, window_seconds: int, patterns: Iterable[str], suspicious_ua: Iterable[str], count_status: bool = True):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.patterns = [re.compile(p) for p in patterns]
        self.ua_patterns = [re.compile(p) for p in suspicious_ua]
        self.hits: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.count_status = count_status

    def is_malicious(self, path: str, ua: str, status: int) -> bool:
        try:
            decoded = unquote_plus(path)[:2048]
        except Exception:
            decoded = path[:2048]
        for rx in self.patterns:
            if rx.search(decoded):
                return True
        for rx in self.ua_patterns:
            if rx.search(ua or ""):
                return True
        for rx in FORBIDDEN_REGEX:
            if rx.search(decoded):
                return True
        if self.count_status and status in SUSPICIOUS_STATUS:
            return True
        return False

    def hit(self, ip: str, when: datetime) -> int:
        dq = self.hits[ip]
        dq.append(when)
        self._trim(ip, when)
        return len(dq)

    def _trim(self, ip: str, now: datetime):
        dq = self.hits[ip]
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def count(self, ip: str, now: datetime) -> int:
        self._trim(ip, now)
        return len(self.hits[ip])

# -----------------------------
# Blocking backend
# -----------------------------
class Blocker:
    def __init__(self, cmd_template: str, dry_run: bool, events_file: Optional[str] = None):
        self.cmd_template = cmd_template
        self.dry_run = dry_run
        self.blocked = set()
        self.events_file = events_file
        if events_file:
            with open(events_file, 'a') as f:
                f.write("")

    def _log_event(self, msg: str):
        ts = datetime.now(timezone.utc).isoformat()
        line = f"[{ts}] {msg}\n"
        print(line, end="")
        if self.events_file:
            with open(self.events_file, 'a') as f:
                f.write(line)

    def block(self, ip: str, reason: str):
        if ip in self.blocked:
            return
        cmd = self.cmd_template.format(ip=ip)
        if self.dry_run:
            self._log_event(f"DRY-RUN block {ip}: {reason} -> {cmd}")
            self.blocked.add(ip)
            return
        self._log_event(f"Blocking {ip}: {reason} -> {cmd}")
        try:
            parts = cmd if isinstance(cmd, list) else cmd.split()
            result = subprocess.run(parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=False)
            self._log_event(f"Command exit {result.returncode}: stdout={result.stdout.strip()} stderr={result.stderr.strip()}")
            if result.returncode == 0:
                self.blocked.add(ip)
        except Exception as e:
            self._log_event(f"ERROR running block command for {ip}: {e}")

# -----------------------------
# Tail implementation
# -----------------------------
STOP = False

def handle_sigint(signum, frame):
    global STOP
    STOP = True

signal.signal(signal.SIGINT, handle_sigint)
signal.signal(signal.SIGTERM, handle_sigint)

def follow(path: str, from_start: bool = False):
    print(f"[DEBUG] Opening log file for tailing: {path}")
    while not os.path.exists(path):
        time.sleep(0.5)
    with open(path, 'r', errors='replace') as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        while not STOP:
            where = f.tell()
            line = f.readline()
            if not line:
                time.sleep(0.25)
                f.seek(where)
            else:
                yield line

def follow_many(logdir: str, from_start: bool = False):
    q = queue.Queue()

    def worker(path):
        for line in follow(path, from_start=from_start):
            q.put((path, line))

    # Recursively walk and tail only files inside subdirectories
    for root, dirs, files in os.walk(logdir):
        if root == logdir:
            # skip files directly in domlogs/
            continue
        for f in files:
            path = os.path.join(root, f)
            print(f"[DEBUG] Starting thread to follow: {path}")
            t = threading.Thread(target=worker, args=(path,), daemon=True)
            t.start()

    while not STOP:
        try:
            yield q.get(timeout=0.5)
        except queue.Empty:
            pass

# -----------------------------
# Utilities
# -----------------------------
def ip_in_any(ip: str, cidrs: Iterable[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return True
    for c in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False

# -----------------------------
# Main loop
# -----------------------------
def run(args):
    detector = Detector(
        threshold=args.threshold,
        window_seconds=args.window,
        patterns=args.patterns or DEFAULT_PATTERNS,
        suspicious_ua=SUSPICIOUS_UA,
        count_status=not args.ignore_status
    )

    blocker = Blocker(cmd_template=args.block_cmd, dry_run=args.dry_run, events_file=args.events_file)

    exclusions = set(args.exclude_ips)
    exclude_nets = set(args.exclude_nets)

    blocked_state_path = args.state_file
    if blocked_state_path and os.path.exists(blocked_state_path):
        try:
            with open(blocked_state_path, 'r') as f:
                blocker.blocked = set(json.load(f))
        except Exception:
            pass

    def persist_state():
        if blocked_state_path:
            try:
                with open(blocked_state_path, 'w') as f:
                    json.dump(sorted(list(blocker.blocked)), f)
            except Exception:
                pass

    try:
        if os.path.isdir(args.log):
            gen = follow_many(args.log, from_start=args.from_start)
        else:
            gen = ((args.log, line) for line in follow(args.log, from_start=args.from_start))

        for src, line in gen:
            m = LOG_RE.match(line.strip())
            if not m:
                continue
            ip = m.group('ip')
            if ip in exclusions or ip_in_any(ip, exclude_nets):
                continue
            when = parse_apache_time(m.group('time'))
            path = m.group('path')
            ua = m.group('ua')
            try:
                status = int(m.group('status'))
            except Exception:
                status = 0

            if detector.is_malicious(path, ua, status):
                n = detector.hit(ip, when)
                if n == 1 and args.verbose:
                    print(f"Suspicious activity from {ip}: first hit at {when.isoformat()} -> {path}")
                if n >= detector.threshold:
                    reason = f"{n} suspicious hits within {args.window}s (last path: {path[:120]})"
                    blocker.block(ip, reason)
                    persist_state()
            elif args.verbose and args.debug_all:
                print(f"Benign line from {ip}: {path}")

            if STOP:
                break
    finally:
        persist_state()

# -----------------------------
# Arg parser
# -----------------------------
def build_arg_parser():
    p = argparse.ArgumentParser(description="Detect and block malicious Apache requests by IP.")
    p.add_argument('--log', required=True, help='Path to Apache access log (file or directory).')
    p.add_argument('--threshold', type=int, default=15, help='Hits required to trigger a block within the time window.')
    p.add_argument('--window', type=int, default=300, help='Rolling window in seconds for counting hits.')
    p.add_argument('--block-cmd', default='iptables -I INPUT -s {ip} -j DROP',
                   help='Command template to block an IP. Use {ip} placeholder.')
    p.add_argument('--exclude-ips', default='', help='Comma-separated list of IPs to ignore.')
    p.add_argument('--exclude-nets', default='127.0.0.0/8,::1/128', help='Comma-separated CIDRs to ignore.')
    p.add_argument('--patterns', nargs='*', help='Override/additional regex patterns.')
    p.add_argument('--ignore-status', action='store_true', help='Do not count suspicious HTTP status codes.')
    p.add_argument('--from-start', action='store_true', help='Read the logfile(s) from the beginning.')
    p.add_argument('--dry-run', action='store_true', help='Do not execute block command, only log.')
    p.add_argument('--events-file', default='', help='Append events to this file.')
    p.add_argument('--state-file', default='/var/lib/malguard-blocked.json', help='Persist already-blocked IPs.')
    p.add_argument('--verbose', action='store_true', help='Print informative messages.')
    p.add_argument('--debug-all', action='store_true', help='With --verbose, also print benign lines.')
    return p

def main(argv=None):
    argv = argv or sys.argv[1:]
    p = build_arg_parser()
    args = p.parse_args(argv)

    args.exclude_ips = [x.strip() for x in (args.exclude_ips.split(',') if args.exclude_ips else []) if x.strip()]
    args.exclude_nets = [x.strip() for x in (args.exclude_nets.split(',') if args.exclude_nets else []) if x.strip()]

    run(args)

if __name__ == '__main__':
    main()

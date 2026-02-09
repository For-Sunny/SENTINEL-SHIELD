#!/usr/bin/env python3
"""
SENTINEL Shield - Attack Simulation Harness
============================================

Writes realistic attack log entries to fake log files, simulating
multi-phase AI-orchestrated attacks flowing through the complete
detection pipeline.

This is the "chaos agent" -- it plays attacker so SENTINEL can prove
it catches attacks end-to-end.

Uses TEST-NET IPs (203.0.113.0/24) per RFC 5737 for attacker addresses.
Uses 198.51.100.0/24 (TEST-NET-2) for benign traffic sources.

Copyright (c) 2026 CIPS Corps. All rights reserved.
"""

import argparse
import os
import sys
import time
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# RFC 5737 TEST-NET ranges -- reserved for documentation/testing
ATTACKER_IP = "203.0.113.50"
ATTACKER_IP_2 = "203.0.113.51"
BENIGN_IP_1 = "198.51.100.10"
BENIGN_IP_2 = "198.51.100.20"
BENIGN_IP_3 = "198.51.100.30"

# Target server hostname (appears in syslog headers)
TARGET_HOST = "sentinel-test"

# Spray usernames (common targets for credential attacks)
SPRAY_USERNAMES = [
    "admin", "root", "deploy", "ubuntu", "ec2-user", "centos",
    "git", "jenkins", "postgres", "mysql", "www-data", "nginx",
    "operator", "test", "backup", "oracle", "ftp", "guest",
    "user", "service", "support", "monitor", "dev", "staging",
    "production", "ansible", "terraform", "docker", "k8s",
    "elastic", "redis", "mongo", "api", "app", "web",
    "mail", "noc", "sysadmin", "devops", "ci", "cd",
    "build", "release", "infra", "platform", "security",
    "audit", "compliance", "data", "analytics", "ml",
]

# Web recon paths (common probe targets)
WEB_RECON_PATHS = [
    "/admin", "/wp-login.php", "/.env", "/api/v1/users",
    "/phpmyadmin", "/wp-admin", "/.git/config", "/.git/HEAD",
    "/server-status", "/actuator", "/console", "/debug",
    "/config.php", "/config.yml", "/database.yml", "/db.php",
    "/backup", "/dump", "/sql", "/.htpasswd", "/.ssh",
    "/manager/html", "/solr", "/jenkins", "/.DS_Store",
    "/xmlrpc.php", "/wp-cron.php", "/cgi-bin", "/adminer",
    "/.well-known", "/wp-content/uploads",
]

# SQL injection probes
SQLI_PROBES = [
    "/search?q=1'+UNION+SELECT+*+FROM+users--",
    "/api/v1/users?id=1+OR+1=1",
    "/login?user=admin'--",
    "/products?cat=1;+DROP+TABLE+users--",
    "/api/search?q='+UNION+ALL+SELECT+NULL,NULL,table_name+FROM+information_schema.tables--",
]

# Directory traversal probes
TRAVERSAL_PROBES = [
    "/../../etc/passwd",
    "/static/../../../etc/shadow",
    "/images/%2e%2e%2f%2e%2e%2fetc/passwd",
    "/download?file=../../../proc/self/environ",
]

# Command injection probes
CMDI_PROBES = [
    "/ping?host=127.0.0.1;+cat+/etc/passwd",
    "/api/exec?cmd=127.0.0.1|+id",
    "/health?check=;+whoami",
    "/api/v1/run?cmd=$(cat+/etc/shadow)",
]

# Common ports for port scanning
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
              993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
              6379, 8080, 8443, 9200, 27017]

# Normal web paths for benign traffic
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products",
    "/api/v1/health", "/static/css/main.css", "/static/js/app.js",
    "/images/logo.png", "/favicon.ico", "/robots.txt",
]

# Normal user agents
NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
]


# ---------------------------------------------------------------------------
# Timestamp Formatting
# ---------------------------------------------------------------------------

def syslog_timestamp(dt: datetime) -> str:
    """Format datetime as syslog timestamp: 'Mon DD HH:MM:SS'

    Note: syslog uses space-padded day (e.g., 'Feb  5' not 'Feb 05').
    """
    month_abbr = dt.strftime("%b")
    day = dt.day
    time_str = dt.strftime("%H:%M:%S")
    # syslog pads single-digit days with a leading space
    if day < 10:
        return f"{month_abbr}  {day} {time_str}"
    else:
        return f"{month_abbr} {day} {time_str}"


def web_timestamp(dt: datetime) -> str:
    """Format datetime as Apache combined log timestamp: 'DD/Mon/YYYY:HH:MM:SS +0000'"""
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


# ---------------------------------------------------------------------------
# Log Line Generators
# ---------------------------------------------------------------------------

def auth_failed_password(dt: datetime, ip: str, username: str, port: int = 54321) -> str:
    """Generate a 'Failed password' auth.log line."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} sshd[{12345 + hash(username) % 1000}]: Failed password for {username} from {ip} port {port} ssh2"


def auth_failed_invalid_user(dt: datetime, ip: str, username: str, port: int = 54321) -> str:
    """Generate a 'Failed password for invalid user' auth.log line."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} sshd[{12345 + hash(username) % 1000}]: Failed password for invalid user {username} from {ip} port {port} ssh2"


def auth_invalid_user(dt: datetime, ip: str, username: str, port: int = 54321) -> str:
    """Generate an 'Invalid user' auth.log line."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} sshd[{12345 + hash(username) % 1000}]: Invalid user {username} from {ip} port {port}"


def auth_accepted_password(dt: datetime, ip: str, username: str, port: int = 54321) -> str:
    """Generate an 'Accepted password' auth.log line."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} sshd[{12345 + hash(username) % 1000}]: Accepted password for {username} from {ip} port {port} ssh2"


def auth_accepted_publickey(dt: datetime, ip: str, username: str, port: int = 54321) -> str:
    """Generate an 'Accepted publickey' auth.log line."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} sshd[{12345 + hash(username) % 1000}]: Accepted publickey for {username} from {ip} port {port} ssh2"


def auth_too_many_failures(dt: datetime, ip: str, username: str, port: int = 54321) -> str:
    """Generate a 'Too many authentication failures' auth.log line."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} sshd[{12345 + hash(username) % 1000}]: Too many authentication failures for {username} from {ip} port {port} ssh2"


def auth_conn_closed(dt: datetime, ip: str, username: str, port: int = 54321) -> str:
    """Generate a 'Connection closed by authenticating user' auth.log line."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} sshd[{12345 + hash(username) % 1000}]: Connection closed by authenticating user {username} {ip} port {port} [preauth]"


def web_request(dt: datetime, ip: str, path: str, status: int = 200,
                size: int = 1234, ua: str = "Mozilla/5.0") -> str:
    """Generate an Apache combined log format line."""
    ts = web_timestamp(dt)
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def syslog_firewall_block(dt: datetime, src_ip: str, dst_port: int) -> str:
    """Generate a UFW BLOCK syslog line (firewall denied connection)."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} kernel: [UFW BLOCK] IN=eth0 SRC={src_ip} DST=10.0.0.1 PROTO=TCP DPT={dst_port}"


def syslog_iptables_drop(dt: datetime, src_ip: str, dst_port: int) -> str:
    """Generate an iptables DROPPED syslog line."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} iptables[9999]: DROPPED: SRC={src_ip} DST=10.0.0.1 DPT={dst_port}"


def syslog_connection_refused(dt: datetime, src_ip: str, dst_port: int) -> str:
    """Generate a connection refused syslog line."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} kernel: TCP: connection refused from {src_ip} port {dst_port}"


def syslog_normal_cron(dt: datetime) -> str:
    """Generate a normal cron syslog line (no external IP -- will be skipped by parser)."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} CRON[1234]: (root) CMD (/usr/bin/certbot renew)"


def syslog_normal_systemd(dt: datetime) -> str:
    """Generate a normal systemd syslog line (no external IP -- will be skipped by parser)."""
    ts = syslog_timestamp(dt)
    return f"{ts} {TARGET_HOST} systemd[1]: Started Daily apt download activities."


# ---------------------------------------------------------------------------
# Scenario Implementations
# ---------------------------------------------------------------------------

def scenario_credential_spray(auth_log: str, now: datetime) -> dict:
    """
    Credential spray attack: recon -> brute force -> success.

    Phase 1 (Recon): 5 SSH connection attempts, different usernames, 10s window
    Phase 2 (Brute Force): 50 failed password attempts, rotating usernames
    Phase 3 (Success): One accepted password after the spray
    """
    lines = []
    stats = {"auth_entries": 0, "web_entries": 0, "syslog_entries": 0}
    t = now

    # Phase 1: Recon -- probe with invalid users
    print(f"  Phase 1: Writing 5 recon probes from {ATTACKER_IP}...")
    for i in range(5):
        username = SPRAY_USERNAMES[i]
        port = 50000 + i
        lines.append(auth_invalid_user(t, ATTACKER_IP, username, port))
        lines.append(auth_conn_closed(t + timedelta(seconds=1), ATTACKER_IP, username, port))
        t += timedelta(seconds=2)
        stats["auth_entries"] += 2

    # Brief pause between phases
    t += timedelta(seconds=3)

    # Phase 2: Brute Force -- 50 failed attempts
    print(f"  Phase 2: Writing 50 failed password attempts from {ATTACKER_IP}...")
    for i in range(50):
        username = SPRAY_USERNAMES[i % len(SPRAY_USERNAMES)]
        port = 51000 + i
        lines.append(auth_failed_password(t, ATTACKER_IP, username, port))
        t += timedelta(milliseconds=200)  # 200ms between attempts -- automated speed
        stats["auth_entries"] += 1

    # After 50 failures, trigger "Too many" for the last few
    for username in ["root", "admin"]:
        lines.append(auth_too_many_failures(t, ATTACKER_IP, username, 52000))
        t += timedelta(seconds=1)
        stats["auth_entries"] += 1

    # Brief pause
    t += timedelta(seconds=2)

    # Phase 3: Success -- compromised credential found
    print(f"  Phase 3: Writing successful login from {ATTACKER_IP}...")
    lines.append(auth_accepted_password(t, ATTACKER_IP, "deploy", 53000))
    stats["auth_entries"] += 1

    # Write to file
    with open(auth_log, "a") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"  Summary: {stats['auth_entries']} auth.log entries written")
    print(f"  Expected detections: AuthFailure x52, BruteForce x2, AuthSuccess x1")
    return stats


def scenario_web_recon_to_exploit(web_log: str, now: datetime) -> dict:
    """
    Web reconnaissance escalating to exploitation.

    Phase 1 (Discovery): 30 requests to common paths, mostly 404s
    Phase 2 (Vulnerability Scan): Traversal, SQLi, command injection probes
    Phase 3 (Exploitation): Successful exploit attempt (200 on injection path)
    """
    lines = []
    stats = {"auth_entries": 0, "web_entries": 0, "syslog_entries": 0}
    t = now

    # Phase 1: Discovery -- probe common paths
    print(f"  Phase 1: Writing 30 web recon probes from {ATTACKER_IP}...")
    for i, path in enumerate(WEB_RECON_PATHS):
        status = 404 if i % 5 != 0 else 403  # Mix of 404 and 403
        lines.append(web_request(t, ATTACKER_IP, path, status, 0, "Mozilla/5.0 (compatible; scanner/1.0)"))
        t += timedelta(milliseconds=100)  # Fast automated scanning
        stats["web_entries"] += 1

    t += timedelta(seconds=2)

    # Phase 2: Vulnerability Scan -- traversal, SQLi, command injection
    print(f"  Phase 2: Writing vulnerability scan probes from {ATTACKER_IP}...")
    for path in TRAVERSAL_PROBES:
        lines.append(web_request(t, ATTACKER_IP, path, 404, 0, "Mozilla/5.0"))
        t += timedelta(milliseconds=300)
        stats["web_entries"] += 1

    for path in SQLI_PROBES:
        lines.append(web_request(t, ATTACKER_IP, path, 500, 0, "sqlmap/1.7"))
        t += timedelta(milliseconds=500)
        stats["web_entries"] += 1

    for path in CMDI_PROBES:
        lines.append(web_request(t, ATTACKER_IP, path, 500, 0, "Mozilla/5.0"))
        t += timedelta(milliseconds=400)
        stats["web_entries"] += 1

    t += timedelta(seconds=2)

    # Phase 3: Exploitation -- one successful injection
    print(f"  Phase 3: Writing successful exploit from {ATTACKER_IP}...")
    lines.append(web_request(
        t, ATTACKER_IP,
        "/api/v1/exec?cmd=$(cat+/etc/shadow)",
        200, 4096, "Mozilla/5.0"
    ))
    stats["web_entries"] += 1

    # Write to file
    with open(web_log, "a") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"  Summary: {stats['web_entries']} web log entries written")
    print(f"  Expected detections: WebProbe/FileAccess x30, DirectoryTraversal x4, SqlInjection x5, CommandInjection x5")
    return stats


def scenario_full_kill_chain(auth_log: str, web_log: str, syslog_path: str, now: datetime) -> dict:
    """
    Full kill chain from a single attacker IP across all three log sources.

    Syslog:   Port scans (connection attempts to multiple ports)
    Auth.log: Credential spray after port scan finds SSH
    Web log:  Web exploit attempts after finding web server
    """
    lines_auth = []
    lines_web = []
    lines_sys = []
    stats = {"auth_entries": 0, "web_entries": 0, "syslog_entries": 0}
    t = now

    # === SYSLOG PHASE: Port scanning ===
    print(f"  Syslog Phase: Writing port scan from {ATTACKER_IP} ({len(SCAN_PORTS)} ports)...")
    for port in SCAN_PORTS:
        lines_sys.append(syslog_firewall_block(t, ATTACKER_IP, port))
        t += timedelta(milliseconds=50)  # Rapid port scan
        stats["syslog_entries"] += 1

    # Some ports get through (22, 80, 443) -- detected as connection attempts
    for port in [22, 80, 443]:
        lines_sys.append(syslog_connection_refused(t, ATTACKER_IP, port))
        t += timedelta(milliseconds=100)
        stats["syslog_entries"] += 1

    t += timedelta(seconds=3)

    # === AUTH PHASE: SSH credential attack (found port 22 open) ===
    print(f"  Auth Phase: Writing SSH credential spray from {ATTACKER_IP}...")
    # 20 failed attempts with different usernames
    for i in range(20):
        username = SPRAY_USERNAMES[i]
        port = 60000 + i
        lines_auth.append(auth_failed_invalid_user(t, ATTACKER_IP, username, port))
        t += timedelta(milliseconds=300)
        stats["auth_entries"] += 1

    # Brute force detection trigger
    lines_auth.append(auth_too_many_failures(t, ATTACKER_IP, "root", 61000))
    stats["auth_entries"] += 1
    t += timedelta(seconds=1)

    # Successful login
    lines_auth.append(auth_accepted_password(t, ATTACKER_IP, "admin", 62000))
    stats["auth_entries"] += 1
    t += timedelta(seconds=2)

    # === WEB PHASE: Web exploitation (found port 80/443 open) ===
    print(f"  Web Phase: Writing web exploitation from {ATTACKER_IP}...")
    # Recon web paths
    for i, path in enumerate(WEB_RECON_PATHS[:15]):
        status = 404 if i % 3 != 0 else 200
        lines_web.append(web_request(t, ATTACKER_IP, path, status, 512, "gobuster/3.1"))
        t += timedelta(milliseconds=50)
        stats["web_entries"] += 1

    # SQL injection attempts
    for path in SQLI_PROBES[:3]:
        lines_web.append(web_request(t, ATTACKER_IP, path, 500, 0, "sqlmap/1.7"))
        t += timedelta(milliseconds=200)
        stats["web_entries"] += 1

    # Command injection attempts
    for path in CMDI_PROBES[:2]:
        lines_web.append(web_request(t, ATTACKER_IP, path, 200, 2048, "Mozilla/5.0"))
        t += timedelta(milliseconds=300)
        stats["web_entries"] += 1

    # Directory traversal
    for path in TRAVERSAL_PROBES[:2]:
        lines_web.append(web_request(t, ATTACKER_IP, path, 404, 0, "Mozilla/5.0"))
        t += timedelta(milliseconds=200)
        stats["web_entries"] += 1

    # Write all files
    with open(syslog_path, "a") as f:
        for line in lines_sys:
            f.write(line + "\n")

    with open(auth_log, "a") as f:
        for line in lines_auth:
            f.write(line + "\n")

    with open(web_log, "a") as f:
        for line in lines_web:
            f.write(line + "\n")

    total = stats["auth_entries"] + stats["web_entries"] + stats["syslog_entries"]
    print(f"  Summary: {stats['syslog_entries']} syslog + {stats['auth_entries']} auth + {stats['web_entries']} web = {total} total")
    print(f"  Expected: High threat score from cross-log-source correlation")
    print(f"  Kill chain: PortScan -> CredentialSpray -> BruteForce -> Success -> WebRecon -> SQLi -> CMDi -> Traversal")
    return stats


def scenario_benign_traffic(auth_log: str, web_log: str, syslog_path: str, now: datetime) -> dict:
    """
    Normal, benign traffic. SENTINEL should NOT trigger alerts on this.

    - Normal SSH logins (accepted, from known IPs)
    - Normal web traffic (200 responses, real user agents, normal paths)
    - Normal syslog (cron, systemd -- no external IPs in message)
    """
    lines_auth = []
    lines_web = []
    lines_sys = []
    stats = {"auth_entries": 0, "web_entries": 0, "syslog_entries": 0}
    t = now

    # Normal SSH logins
    print(f"  Auth: Writing 5 normal SSH logins...")
    for i, (ip, user) in enumerate([
        (BENIGN_IP_1, "deploy"),
        (BENIGN_IP_2, "admin"),
        (BENIGN_IP_1, "deploy"),
        (BENIGN_IP_3, "git"),
        (BENIGN_IP_2, "admin"),
    ]):
        lines_auth.append(auth_accepted_publickey(t, ip, user, 40000 + i))
        t += timedelta(minutes=10)  # Spread out over time -- human pace
        stats["auth_entries"] += 1

    # Normal web traffic
    print(f"  Web: Writing 15 normal web requests...")
    t = now
    for i in range(15):
        ip = [BENIGN_IP_1, BENIGN_IP_2, BENIGN_IP_3][i % 3]
        path = NORMAL_PATHS[i % len(NORMAL_PATHS)]
        ua = NORMAL_USER_AGENTS[i % len(NORMAL_USER_AGENTS)]
        lines_web.append(web_request(t, ip, path, 200, 4096 + i * 100, ua))
        t += timedelta(seconds=30)  # Normal browsing pace
        stats["web_entries"] += 1

    # Normal syslog -- these have no external IPs so should be skipped by parser
    print(f"  Syslog: Writing 5 normal system messages...")
    t = now
    for i in range(5):
        if i % 2 == 0:
            lines_sys.append(syslog_normal_cron(t))
        else:
            lines_sys.append(syslog_normal_systemd(t))
        t += timedelta(minutes=5)
        stats["syslog_entries"] += 1

    # Write all files
    with open(auth_log, "a") as f:
        for line in lines_auth:
            f.write(line + "\n")

    with open(web_log, "a") as f:
        for line in lines_web:
            f.write(line + "\n")

    with open(syslog_path, "a") as f:
        for line in lines_sys:
            f.write(line + "\n")

    total = stats["auth_entries"] + stats["web_entries"] + stats["syslog_entries"]
    print(f"  Summary: {stats['syslog_entries']} syslog + {stats['auth_entries']} auth + {stats['web_entries']} web = {total} total")
    print(f"  Expected: NO alerts. Threat score < 0.2 for all benign IPs.")
    print(f"  Syslog entries contain no external IPs -- parser should return None for all.")
    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL Shield Attack Simulator -- writes realistic attack logs for integration testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Scenarios:
  credential_spray     SSH credential spray attack (auth.log only)
  web_recon_to_exploit Web recon escalating to exploitation (web log only)
  full_kill_chain      Multi-log-source attack (syslog + auth + web)
  benign_traffic       Normal traffic -- should NOT trigger alerts
  all                  Run all scenarios sequentially

Examples:
  python attack_simulator.py --scenario credential_spray --auth-log /tmp/test/auth.log
  python attack_simulator.py --scenario full_kill_chain --auth-log /tmp/auth.log --web-log /tmp/access.log --syslog-path /tmp/syslog
  python attack_simulator.py --scenario all --auth-log auth.log --web-log access.log --syslog-path syslog.log
"""
    )
    parser.add_argument("--auth-log", default="auth.log",
                        help="Path to auth log file (default: auth.log)")
    parser.add_argument("--web-log", default="access.log",
                        help="Path to web access log file (default: access.log)")
    parser.add_argument("--syslog-path", default="syslog.log",
                        help="Path to syslog file (default: syslog.log)")
    parser.add_argument("--scenario", required=True,
                        choices=["credential_spray", "web_recon_to_exploit",
                                 "full_kill_chain", "benign_traffic", "all"],
                        help="Attack scenario to simulate")

    args = parser.parse_args()

    # Ensure parent directories exist
    for path in [args.auth_log, args.web_log, args.syslog_path]:
        parent = os.path.dirname(path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    # Use current UTC time as base
    now = datetime.now(timezone.utc)

    print("=" * 70)
    print("SENTINEL Shield Attack Simulator")
    print("=" * 70)
    print(f"  Attacker IP:   {ATTACKER_IP} (RFC 5737 TEST-NET-3)")
    print(f"  Auth log:      {args.auth_log}")
    print(f"  Web log:       {args.web_log}")
    print(f"  Syslog:        {args.syslog_path}")
    print(f"  Scenario:      {args.scenario}")
    print(f"  Base time:     {now.isoformat()}")
    print("=" * 70)

    total_stats = {"auth_entries": 0, "web_entries": 0, "syslog_entries": 0}

    def merge_stats(s):
        for k in total_stats:
            total_stats[k] += s.get(k, 0)

    if args.scenario in ("credential_spray", "all"):
        print("\n--- Scenario: credential_spray ---")
        s = scenario_credential_spray(args.auth_log, now)
        merge_stats(s)
        time.sleep(1)
        now += timedelta(seconds=30)

    if args.scenario in ("web_recon_to_exploit", "all"):
        print("\n--- Scenario: web_recon_to_exploit ---")
        s = scenario_web_recon_to_exploit(args.web_log, now)
        merge_stats(s)
        time.sleep(1)
        now += timedelta(seconds=30)

    if args.scenario in ("full_kill_chain", "all"):
        print("\n--- Scenario: full_kill_chain ---")
        s = scenario_full_kill_chain(args.auth_log, args.web_log, args.syslog_path, now)
        merge_stats(s)
        time.sleep(1)
        now += timedelta(seconds=30)

    if args.scenario in ("benign_traffic", "all"):
        print("\n--- Scenario: benign_traffic ---")
        s = scenario_benign_traffic(args.auth_log, args.web_log, args.syslog_path, now)
        merge_stats(s)

    grand_total = sum(total_stats.values())
    print("\n" + "=" * 70)
    print("SIMULATION COMPLETE")
    print("=" * 70)
    print(f"  Auth log entries:   {total_stats['auth_entries']}")
    print(f"  Web log entries:    {total_stats['web_entries']}")
    print(f"  Syslog entries:     {total_stats['syslog_entries']}")
    print(f"  Total entries:      {grand_total}")
    print("=" * 70)


if __name__ == "__main__":
    main()

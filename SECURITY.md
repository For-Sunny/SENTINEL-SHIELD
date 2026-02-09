# Security Policy

## Reporting Vulnerabilities

Email **glass@cipscorps.io** with subject line `[SENTINEL-SHIELD SECURITY]`.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what can an attacker do with this?)
- Your suggested fix, if you have one

Do not open a public GitHub issue for security vulnerabilities.

## Response Timeline

- **Acknowledgment**: Within 48 hours of report.
- **Triage**: Within 7 days. We will confirm whether this is a valid vulnerability and assign severity.
- **Fix**: Critical and High severity issues within 30 days. Medium within 90 days.
- **Disclosure**: Coordinated disclosure after a fix is available. We will credit the reporter unless they prefer anonymity.

## Scope

### In Scope

- Command injection via log file content that bypasses IP validation
- Denial of service through crafted log entries (memory exhaustion, CPU spin)
- Firewall rule bypass (blocking evasion)
- Private IP blocking bypass (the blocker should never block 10.x, 172.16-31.x, 192.168.x, or loopback)
- Information disclosure through the alert log, webhook payload, or email queue
- Path traversal via configured file paths
- Any way to make SENTINEL perform offensive actions (it should be architecturally impossible)
- Vulnerabilities in dependencies (Cargo.toml crates)

### Out of Scope

- Attacks requiring root access to the machine already running SENTINEL (if you have root, you don't need SENTINEL to be vulnerable)
- Log file tampering by an attacker who already has write access to the log files being monitored
- The dashboard (it is a stub and serves nothing)
- Social engineering of the administrator
- Denial of service against the machine itself (not SENTINEL-specific)

## Design Principles

SENTINEL Shield is a security tool. We hold ourselves to a higher standard:

- **No shell injection surface.** IPs are validated through Rust's `std::net::IpAddr` type system before any command execution. The `safe_ip_string()` function uses `IpAddr::to_string()` which can only produce valid IP notation.
- **No outbound attack capability.** The only outbound connections are webhook POSTs to URLs the administrator configures. There is no scanning, probing, or exploitation code.
- **Fail safe.** Response failures (webhook timeout, firewall command failure) are logged and swallowed. A broken webhook should not crash the daemon.
- **Private IP protection.** The blocker refuses to block private, loopback, link-local, broadcast, and unspecified addresses.
- **Minimal privilege.** SENTINEL needs read access to log files and (if blocking is enabled) permission to modify firewall rules. Nothing else.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

We will support the latest minor release with security patches.

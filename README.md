# SENTINEL Shield

A Rust security daemon that watches your server logs, detects AI-orchestrated cyberattacks, and blocks malicious IPs. Built for small companies that can't afford a SOC team but still face automated threats.

SENTINEL Shield is defense-only by architecture. It cannot attack. It has no offensive capability. It watches, detects, blocks, and learns. Nothing else.

## What It Detects

SENTINEL scores threats across three dimensions, backed by a learning layer:

**Velocity** -- How fast is this source generating events? Humans browse. Bots spray. Fifty failed SSH logins in ten seconds is not a person.

**Coverage** -- How broadly is this source probing? A legitimate user hits one endpoint. An automated scanner hits twenty ports and fifteen paths in a minute.

**Correlation** -- How quickly does reconnaissance lead to exploitation? A human scans Tuesday, exploits Thursday. An AI agent discovers an open port and attempts exploitation in under a second.

**Pattern Learning** -- A Hebbian graph tracks which attack phases follow which. The more attacks SENTINEL observes, the better it predicts the next step. Edges strengthen through co-occurrence and decay over time. No retraining required.

## What It Does When It Detects

Three things:

1. **Blocks the IP** via system firewall (iptables on Linux, netsh on Windows). Disabled by default -- runs in dry-run mode until you're ready.
2. **Alerts you** via JSONL log file, webhook (Slack, Discord, PagerDuty, Teams), or email queue (.eml files for SMTP pickup).
3. **Learns the pattern** by strengthening Hebbian edges between observed attack phases. Next time the same progression appears, detection is faster.

## Architecture

```
                    Log Files
                   /    |    \
                  /     |     \
           auth.log  access.log  syslog
              |        |          |
              v        v          v
         +---------+---------+---------+
         | AuthLog | WebLog  | Syslog  |   Log Source Parsers
         | Parser  | Parser  | Parser  |   (regex-based, zero-copy where possible)
         +---------+---------+---------+
                   \    |    /
                    v   v   v
              +------------------+
              |  LogEvent        |   Normalized event with IP, port,
              |  (intermediate)  |   endpoint, event type, raw line
              +------------------+
                       |
                       v
              +------------------+
              | DetectionEvent   |   Classified: AuthFailure, WebProbe,
              | (core type)      |   ExploitAttempt, BruteForce, etc.
              +------------------+
                       |
                       v
              +------------------+
              | Detection Engine |   Groups events by source IP into
              |                  |   AttackSessions, runs three scorers
              +------------------+
               /       |       \
              v        v        v
         +--------+--------+--------+
         |Velocity|Coverage|Correlat.|  Sub-scorers (each 0.0-1.0)
         | (0.40) | (0.35) | (0.25) |  (default weights)
         +--------+--------+--------+
                   \   |   /
                    v  v  v
              +------------------+
              | Threat Scorer    |   Weighted combination -> ThreatScore
              | (combined 0-1.0) |   Threshold check (default 0.7)
              +------------------+
                       |
                       v
              +------------------+
              |  Attack Graph    |   Hebbian learning on phase transitions
              |  (10x10 matrix)  |   MITRE-seeded, decay, persistence
              +------------------+
                       |
                       v
              +------------------+
              | Response         |   Block IP, log alert, webhook,
              | Orchestrator     |   email queue
              +------------------+
```

## Quick Start

```bash
# Build
cargo build --release

# Generate default config
./target/release/sentinel-shield init-config

# Edit the config -- point to your log files
# (see Configuration Reference below)
vim sentinel-shield.toml

# Start in dry-run mode (blocking disabled by default)
RUST_LOG=info ./target/release/sentinel-shield start

# Check status
./target/release/sentinel-shield status

# Stop
./target/release/sentinel-shield stop
```

## Configuration Reference

SENTINEL reads from `sentinel-shield.toml` (or the path you pass with `-c`). Run `init-config` to generate a default file with comments.

### `[general]`

| Field | Default | Description |
|-------|---------|-------------|
| `eval_interval_secs` | `10` | How often the engine polls for new log lines and evaluates sessions. |
| `data_dir` | `./sentinel-data` | Where SENTINEL stores its state (graph, PID file, alerts). |
| `graph_state_file` | `./sentinel-data/graph.json` | Path to the persisted Hebbian graph. Survives restarts. |

### `[detection]`

| Field | Default | Description |
|-------|---------|-------------|
| `threat_threshold` | `0.7` | Combined score above which an IP is considered a threat (0.0-1.0). |
| `velocity_weight` | `0.4` | Weight for velocity in the combined score. |
| `coverage_weight` | `0.35` | Weight for coverage in the combined score. |
| `correlation_weight` | `0.25` | Weight for correlation in the combined score. |
| `velocity_window_secs` | `60` | Sliding window for counting events per source. |
| `velocity_saturation` | `100` | Events in the window at which velocity score hits 1.0. |
| `coverage_saturation` | `20` | Unique targets (ports + endpoints) at which coverage hits 1.0. |
| `correlation_min_gap_secs` | `1` | Recon-to-exploit gap below this scores 1.0 (instant pivot). |
| `correlation_max_gap_secs` | `300` | Recon-to-exploit gap above this scores 0.0 (uncorrelated). |

Weights should sum to 1.0. The defaults are tuned for AI attack detection: speed is the primary signal (0.4), breadth of probing is secondary (0.35), and tight recon-to-exploit timing confirms (0.25).

### `[log_sources]`

| Field | Default | Description |
|-------|---------|-------------|
| `auth_log_paths` | `[]` | Paths to auth log files. Example: `["/var/log/auth.log"]` |
| `web_log_paths` | `[]` | Paths to Apache/Nginx combined format access logs. |
| `syslog_paths` | `[]` | Paths to syslog files. |

You can watch multiple files per source type. SENTINEL tracks byte offsets and handles log rotation.

### `[response]`

| Field | Default | Description |
|-------|---------|-------------|
| `blocking_enabled` | `false` | Whether to actually execute firewall blocks. Start with `false`. |
| `alert_log_path` | `./sentinel-data/alerts.log` | Path to the JSONL alert log. |
| `webhook_url` | `null` | Optional webhook URL for real-time alerts (Slack, Discord, etc.). |
| `alert_email` | `null` | Optional email address. Writes .eml files to `{data_dir}/email_queue/`. |
| `block_duration_secs` | `3600` | How long an IP stays blocked. `null` = permanent until manual unblock. |

### `[dashboard]`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Whether to start the dashboard HTTP server. |
| `bind_address` | `127.0.0.1` | Bind address. Keep this localhost unless you know what you're doing. |
| `port` | `8080` | Dashboard port. |

**Note:** The dashboard is currently a stub. It creates the server struct but does not serve HTTP yet. The `status` CLI command is the current way to inspect state.

## Learning Control

The Hebbian graph learns continuously by default. Five runtime commands let operators control that behavior without restarting the daemon.

| Command | Method | What It Does |
|---------|--------|-------------|
| `learning_status` | GET | Returns current state: enabled/paused, rate multiplier, batch frequency. |
| `learning_pause` | POST | Pauses learning. Detection continues unchanged -- the graph just stops updating. |
| `learning_resume` | POST | Resumes learning from where it left off. |
| `learning_set_rate` | POST | Sets a rate multiplier (0.0-2.0) on the Hebbian learning rate. 0.5 = half speed. 2.0 = double. Clamped at boundaries. |
| `learning_set_batch_freq` | POST | Learn every N event batches instead of every batch. Set to 3 and the graph updates on every third batch, reducing CPU cost at the expense of granularity. Minimum 1. |

These commands are transport-agnostic. The handler layer (`src/dashboard/learning_api.rs`) accepts a command name and optional value, returns a JSON response with the operation result and current state. Wire them to HTTP, CLI, or MCP -- the handlers don't care.

**When to use this:**

- **Incident response** -- Pause learning during a known attack so the graph doesn't over-fit to one adversary's pattern.
- **Tuning** -- Lower the rate multiplier while observing how the graph evolves. Raise it when you trust the input quality.
- **Cost control** -- On high-traffic hosts, set batch frequency to 5 or 10 so the graph learns from a sample rather than every batch.

Detection scoring is unaffected by these controls. Pausing learning pauses the graph, not the shield.

## How Detection Works

### Threat Scoring

Each source IP accumulates events into an AttackSession. Every evaluation cycle, SENTINEL computes three sub-scores:

**Velocity** = events_in_window / saturation_threshold, clamped to [0.0, 1.0]. A 60-second sliding window counts recent events. 100 events in a minute saturates to 1.0.

**Coverage** = (unique_ports + unique_endpoints) / saturation_threshold. Twenty unique targets saturates to 1.0. An IP that hits port 22, port 80, port 443, `/admin`, `/.env`, and `/wp-login` scores higher than one that repeatedly hits port 22.

**Correlation** = how quickly reconnaissance leads to exploitation from the same source. SENTINEL pairs each exploit event with the nearest preceding recon event and measures the time gap. Below 1 second scores 1.0 (instant pivot, clearly automated). Above 300 seconds scores 0.0 (uncorrelated). Linear decay between.

**Combined** = (velocity * 0.4) + (coverage * 0.35) + (correlation * 0.25). If this exceeds the threat threshold (default 0.7), the source triggers a response.

### Hebbian Graph

SENTINEL maintains a 10x10 directed graph where nodes represent attack phases (Reconnaissance, Enumeration, VulnerabilityScan, CredentialAttack, Exploitation, PrivilegeEscalation, LateralMovement, DataExfiltration, Persistence, CommandControl).

When two attack phases are observed from the same source within a time window, the edge between them strengthens. The Hebbian rule: `weight += learning_rate * activation_a * activation_b`.

The graph starts seeded with MITRE ATT&CK common progressions (Recon -> Enumeration at 2.0, VulnerabilityScan -> Exploitation at 2.5, etc.) so it works from first deployment. Real observations modify these weights over time.

Temporal decay (0.5% per cycle) prevents stale patterns from persisting. Edges below 0.001 are zeroed out. The graph persists to disk as JSON and survives restarts.

### Kill Chain Pattern Matching

Ten known attack patterns are matched against each source's observed action sequence:

| Pattern | Severity | Sequence |
|---------|----------|----------|
| Full Kill Chain (KC-001) | Critical | Recon -> Enum -> VulnScan -> Exploit -> PrivEsc -> Exfil |
| Credential Spray (CS-001) | High | Recon -> Enum -> CredentialAttack -> Exploit |
| Ransomware (RW-001) | Critical | Exploit -> PrivEsc -> Persistence -> LateralMovement |
| Lateral Movement (LM-001) | Critical | Exploit -> PrivEsc -> LateralMovement -> C2 |
| Data Theft via C2 (DT-001) | Critical | C2 -> Exfil |
| Automated Scanner (AS-001) | Medium | Recon -> VulnScan -> Enum |
| Brute Force (BF-001) | High | Enum -> CredentialAttack -> CredentialAttack |
| Persistence (SC-001) | High | Exploit -> Persistence -> C2 |
| Pivot and Exfil (PE-001) | Critical | LateralMovement -> Recon -> PrivEsc -> Exfil |
| Initial Access Probe (IA-001) | Low | Recon -> Enum |

Patterns use subsequence matching with configurable minimum match counts. Partial matches are tracked as "in progress."

## Log Sources

### auth.log

Parses Linux auth logs (`/var/log/auth.log`, `/var/log/secure`). Handles:

- Failed password (with and without "invalid user")
- Accepted password / publickey
- Invalid user connection attempts
- "Too many authentication failures" (classified as BruteForce)
- Connection closed during auth
- Disconnected from user

String matching first, regex only for IP/port extraction. Non-matching lines cost almost nothing.

### Apache/Nginx Access Logs

Parses combined log format. Detects:

- SQL injection (UNION SELECT, OR 1=1, DROP TABLE, SLEEP, BENCHMARK, etc.)
- Command injection (semicolon/pipe + shell commands, $(), backticks)
- Directory traversal (../, %2e%2e, /etc/passwd, /proc/self)
- Suspicious paths (/.env, /.git, /wp-admin, /phpmyadmin, /actuator, /server-status, etc.)
- Scanner user agents (sqlmap, nikto, nmap, gobuster, nuclei, hydra, masscan, and 30+ more)

### Syslog

Generic syslog parser. Extracts IPs from message bodies and classifies by keyword matching:

- Firewall blocks (UFW, iptables, nftables) -> Reconnaissance
- Auth failure keywords -> AuthFailure
- Auth success keywords -> AuthSuccess
- Denied/refused/blocked keywords -> PortProbe
- Error/failure keywords -> Suspicious

Skips loopback and unspecified addresses. Lines without external IPs return nothing.

## Alert Channels

**JSONL File** (always active) -- One JSON object per line appended to the alert log. Each entry contains timestamp, source IP, threat score breakdown (velocity, coverage, correlation), threat level label, and reason. Parse with `jq`, `grep`, or any JSON tool.

**Webhook** (optional) -- HTTP POST with JSON payload to any URL. Compatible with Slack, Discord, PagerDuty, Teams, and generic endpoints. 5-second timeout. Failures are logged but don't crash the daemon.

**Email Queue** (optional) -- Writes .eml files to `{data_dir}/email_queue/`. A separate process (cron job, sendmail pickup, systemd timer) delivers them via SMTP. This avoids baking SMTP complexity into the daemon.

## Defense-Only Design

SENTINEL Shield cannot attack. This is not a policy decision. It is an architectural constraint.

The codebase contains:

- Log parsers that read files
- Scorers that compute numbers
- A graph that learns edge weights
- A blocker that adds firewall rules to DROP inbound traffic
- Alerters that write files and POST webhooks

There is no network scanning code. No exploit generation. No payload construction. No outbound connection to target systems. The blocker uses `iptables -A INPUT ... -j DROP` and `netsh advfirewall ... action=block` -- inbound-only rules that add the IP to a deny list. The only outbound connection is the webhook POST to your own alert endpoint.

The attack patterns in the graph are detection signatures, not instructions. They describe "if we see A then B, an attack is likely" -- the same information published in MITRE ATT&CK documentation.

Private IPs (10.x, 172.16-31.x, 192.168.x, loopback) are never blocked to prevent accidental lockout.

## Testing

### Rust Tests

```bash
# Unit tests (all modules)
cargo test

# With output
cargo test -- --nocapture

# Specific module
cargo test detection::velocity
cargo test graph::patterns
cargo test log_sources::auth_log
```

The test suite includes:
- Unit tests for each scorer, parser, and graph operation
- Integration tests that create fake log files, feed them through the full pipeline, and verify threat scores match expectations
- Tests for both attack scenarios (credential spray, full kill chain, web exploit) and benign traffic (should NOT trigger)

### Attack Simulator

A Python script that writes realistic attack log entries for end-to-end testing:

```bash
# Run all attack scenarios
python tests/attack_simulator.py --scenario all \
  --auth-log /tmp/test/auth.log \
  --web-log /tmp/test/access.log \
  --syslog-path /tmp/test/syslog.log

# Individual scenarios
python tests/attack_simulator.py --scenario credential_spray --auth-log /tmp/auth.log
python tests/attack_simulator.py --scenario web_recon_to_exploit --web-log /tmp/access.log
python tests/attack_simulator.py --scenario full_kill_chain \
  --auth-log /tmp/auth.log --web-log /tmp/access.log --syslog-path /tmp/syslog.log
python tests/attack_simulator.py --scenario benign_traffic \
  --auth-log /tmp/auth.log --web-log /tmp/access.log --syslog-path /tmp/syslog.log
```

Uses RFC 5737 TEST-NET addresses (203.0.113.0/24 for attackers, 198.51.100.0/24 for benign traffic).

## Current Status

**Working:**
- Full detection pipeline (log parsing -> event classification -> session scoring -> response)
- Three log source parsers (auth.log, Apache/Nginx combined, syslog)
- Three detection dimensions (velocity, coverage, correlation)
- Hebbian attack graph with MITRE-seeded weights, learning, decay, persistence
- Runtime learning control (pause, resume, rate adjustment, batch frequency)
- Ten MITRE-based kill chain patterns with subsequence matching
- IP blocking via iptables (Linux) and netsh (Windows)
- Alert logging (JSONL file), webhook notifications, email queue
- CLI with start/stop/status/init-config commands
- Graceful shutdown with state persistence
- Session pruning and graph maintenance
- Comprehensive test suite including integration tests and attack simulator

**Stubbed:**
- Dashboard HTTP server (struct exists, endpoints defined, `run()` returns immediately)
- Burst velocity detection (`calculate_burst_velocity` implemented but not wired into the main scorer)
- Weighted coverage scoring (`calculate_weighted_coverage_score` implemented but not used by default)
- Phase correlation (`calculate_phase_correlation` implemented but not used by default)
- `EscalateMonitoring` response type (logged, not implemented)

**Planned:**
- Dashboard with real-time session/graph visualization
- Block expiry (automatic unblock after configured duration)
- IPv6 support in log parsers (currently IPv4 only for auth.log and syslog extraction)
- Systemd service file and packaging

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Built By

[CIPS Corp](https://cipscorps.io) -- glass@cipscorps.io

Built in a basement. No venture capital. No oversight committee. Just a belief that small companies deserve security tools that actually work.

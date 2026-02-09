# Changelog

## v0.1.0 - 2026-02-08

Initial release.

### Detection Engine
- Three-dimensional threat scoring: velocity, coverage, correlation
- Configurable weights and saturation thresholds
- Per-source-IP attack sessions with event accumulation
- Threat level classification (Critical, High, Medium, Low, Minimal)
- Session pruning for idle sources

### Log Source Parsers
- **auth.log**: Failed password, invalid user, accepted password/publickey, brute force triggers, connection close/disconnect
- **Apache/Nginx access logs**: SQL injection, command injection, directory traversal, suspicious path probing, scanner user-agent detection
- **Syslog**: Firewall block extraction (UFW, iptables, nftables), IP extraction with loopback filtering, keyword-based event classification
- Byte offset tracking for efficient polling
- Multiple files per source type

### Hebbian Attack Graph
- 10-node directed graph representing MITRE ATT&CK kill chain phases
- MITRE-seeded initial edge weights
- Hebbian learning: edges strengthen when phases co-occur from the same source
- Temporal decay (configurable rate, default 0.5% per cycle)
- Per-source observation tracking
- Graph persistence to JSON
- Threat score contribution from edge weights

### Kill Chain Pattern Matching
- 10 known attack patterns based on MITRE ATT&CK progressions
- Subsequence matching with configurable minimum match counts
- Partial match detection for in-progress attacks
- Severity-ranked output (Critical, High, Medium, Low)
- Chain strength weighted by Hebbian edge weights

### Response System
- IP blocking via iptables (Linux) and netsh advfirewall (Windows)
- Private IP protection (refuses to block 10.x, 172.16-31.x, 192.168.x, loopback)
- Command injection prevention via IpAddr type validation
- JSONL alert logging with full score breakdown
- Webhook notifications (HTTP POST, 5-second timeout, non-fatal failures)
- Email queue (.eml file generation for SMTP pickup)
- Block deduplication
- Rule cleanup (clear all SENTINEL-tagged firewall rules)

### CLI
- `start` -- Start the daemon (foreground or background)
- `stop` -- Stop a running daemon via PID file
- `status` -- Show daemon status
- `init-config` -- Generate default configuration file

### Testing
- Unit tests for velocity, coverage, correlation scorers
- Unit tests for all three log parsers
- Unit tests for graph learning, decay, and pattern matching
- Unit tests for blocker safety (private IP rejection, injection prevention)
- Unit tests for alerter (JSONL format, webhook validation, email generation)
- Integration tests: credential spray, full kill chain, web exploitation, benign traffic, graph learning, response generation, independent source scoring, parser completeness
- Python attack simulator with four scenarios (credential spray, web recon-to-exploit, full kill chain, benign traffic)

### Stubbed
- Dashboard HTTP server (struct and endpoint definitions only)
- Burst velocity detection (implemented, not wired in)
- Weighted coverage scoring (implemented, not used by default)
- Adaptive weight scoring (implemented, not called from main loop)
- Phase correlation (implemented, not used by default)
- EscalateMonitoring response type (logged only)

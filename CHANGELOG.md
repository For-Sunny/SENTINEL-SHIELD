# Changelog

## v0.1.1 - 2026-02-10

### Fixed
- **Double-learn bug** -- The Hebbian graph was learning twice per event batch. `main.rs` called `update_graph()` and `learn()` after `process_events()`, but `process_events()` already performed both operations internally. The duplicates in the main loop have been removed. Learning now happens once per batch, inside the detection pipeline where it belongs. The main loop handles only prune and save.

### Added
- **Learning control valve** -- Runtime control over the Hebbian graph's learning behavior. Operators can pause, resume, adjust learning rate, and set batch frequency without restarting the daemon.
  - `LearningControl` struct (`src/learning_control.rs`) with `should_learn()`, `effective_rate()`, `pause()`, `resume()`, `set_rate()`, `set_batch_frequency()`
  - Transport-agnostic API handlers (`src/dashboard/learning_api.rs`) for 5 commands: `learning_status`, `learning_pause`, `learning_resume`, `learning_set_rate`, `learning_set_batch_freq`
  - `DetectionEngine` checks `LearningControl` before calling `graph.learn_with_rate()`
  - `EdgeMatrix::strengthen_with_rate()` accepts external rate multiplier from the control valve
  - `AttackGraph::learn_with_rate()` passes the rate through to edge strengthening
  - Unit tests for control state, batch frequency, rate clamping, pause/resume, JSON roundtrip, and API routing

### Changed
- `src/graph/edges.rs` -- `strengthen()` now delegates to `strengthen_with_rate()` with rate 1.0
- `src/graph/mod.rs` -- `learn()` now delegates to `learn_with_rate()` with rate 1.0
- `src/detection/mod.rs` -- `process_events()` gates learning through `LearningControl` and passes the effective rate
- `src/main.rs` -- Main loop no longer calls `update_graph()` or `learn()` directly. Comment clarifies that learning happens inside `process_events()`

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
- Phase correlation (implemented, not used by default)
- EscalateMonitoring response type (logged only)

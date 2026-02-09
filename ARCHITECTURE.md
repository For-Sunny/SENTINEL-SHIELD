# Architecture

Technical reference for contributors. Read this if you want to understand the internals, add a log source, or add an attack pattern.

## Module Map

```
sentinel-shield/
  src/
    lib.rs                   Core types, config structs, error types
    main.rs                  CLI (start, stop, status, init-config), daemon loop
    detection/
      mod.rs                 DetectionEngine -- groups events by IP, runs scorers
      velocity.rs            Events-per-window scorer (sliding window, saturation)
      coverage.rs            Unique-targets scorer (ports + endpoints)
      correlation.rs         Recon-to-exploit timing scorer
      scorer.rs              Score formatting, threat level labels, adaptive scoring (stubbed)
    log_sources/
      mod.rs                 LogSourceRegistry -- polls all sources, byte offset tracking
      auth_log.rs            /var/log/auth.log parser (SSH events)
      web_log.rs             Apache/Nginx combined format parser (web attacks)
      syslog.rs              Generic syslog parser (firewall blocks, IP extraction)
    graph/
      mod.rs                 AttackGraph -- Hebbian learning, chain detection, persistence
      nodes.rs               ActionType enum (10 attack phases), Observation, SourceTracker
      edges.rs               EdgeMatrix (10x10), Hebbian update rule, decay, MITRE seeding
      patterns.rs            Known attack patterns (10), subsequence matching, severity
    response/
      mod.rs                 ResponseOrchestrator -- decides what to do, delegates
      blocker.rs             IP blocking (iptables/netsh), private IP protection
      alerter.rs             JSONL logging, webhook POST, email queue (.eml)
    dashboard/
      mod.rs                 DashboardServer stub (endpoints defined, not serving)
  tests/
    integration.rs           10 end-to-end pipeline tests
    attack_simulator.py      4-scenario log generator for testing
```

## Data Flow

A log line enters the system and flows through five stages.

### Stage 1: Log Polling

`LogSourceRegistry` holds a list of `LogSource` trait objects. Each source tracks its byte offset in the file. On each poll cycle (`eval_interval_secs`), the registry reads new lines from each file, calls the parser, and collects `DetectionEvent` structs.

```
auth.log line -----> AuthLogSource.parse_line() -----> Option<DetectionEvent>
access.log line ---> WebLogSource.parse_line() ------> Option<DetectionEvent>
syslog line -------> SyslogSource.parse_line() ------> Option<DetectionEvent>
```

Lines that don't match any parser pattern return `None` and cost almost nothing. The parsers use string matching first (fast path) and regex only for IP/port extraction.

### Stage 2: Event Classification

Each `DetectionEvent` carries:
- `source_ip: IpAddr` -- who generated this event
- `event_type: EventType` -- what happened (AuthFailure, WebProbe, ExploitAttempt, BruteForce, etc.)
- `target_port: Option<u16>` -- which port was targeted
- `target_endpoint: Option<String>` -- which URL path was hit
- `source: LogSourceType` -- which parser produced this
- `raw_line: String` -- the original log line

The `EventType` enum classifies events at parse time. The auth parser knows that "Failed password" is `AuthFailure` and "Too many authentication failures" is `BruteForce`. The web parser knows that `UNION SELECT` in a URL is `ExploitAttempt`. The syslog parser knows that `[UFW BLOCK]` is `Reconnaissance`.

### Stage 3: Session Grouping and Scoring

`DetectionEngine.process_events()` groups events by `source_ip` into `AttackSession` structs. Each session accumulates:
- All events from that IP
- Unique targeted ports
- Unique targeted endpoints
- First/last seen timestamps

After grouping, three scorers run against each session:

**Velocity** (`velocity.rs`):
```
events_in_window = events where timestamp > (now - velocity_window_secs)
velocity_score = events_in_window / velocity_saturation
clamped to [0.0, 1.0]
```

**Coverage** (`coverage.rs`):
```
unique_targets = targeted_ports.len() + targeted_endpoints.len()
coverage_score = unique_targets / coverage_saturation
clamped to [0.0, 1.0]
```

**Correlation** (`correlation.rs`):
```
For each ExploitAttempt event:
  Find nearest preceding Reconnaissance/WebProbe event from same source
  gap_secs = exploit.timestamp - recon.timestamp
  If gap < min_gap: score = 1.0
  If gap > max_gap: score = 0.0
  Else: score = 1.0 - (gap - min_gap) / (max_gap - min_gap)
correlation_score = maximum of all pair scores
```

**Combined**:
```
combined = velocity * 0.4 + coverage * 0.35 + correlation * 0.25
```

Sessions where `combined >= threat_threshold` are returned as threatening.

### Stage 4: Graph Learning

The `AttackGraph` maintains a 10x10 directed adjacency matrix where nodes are attack phases:

```
     Recon  Enum  VulnScan  Cred  Exploit  PrivEsc  Lateral  Exfil  Persist  C2
Recon  [0.3   2.0    1.5    1.5    0.0      0.0     0.0     0.0     0.0    0.0]
Enum   [0.0   0.3    1.8    1.8    0.0      0.0     0.0     0.0     0.0    0.0]
VulnS  [0.0   0.0    0.0    0.0    2.5      0.0     0.0     0.0     0.0    0.0]
Cred   [0.0   0.0    0.0    0.5    1.5      0.0     1.2     0.0     0.0    0.0]
Expl   [0.0   0.0    0.0    0.0    0.0      2.0     0.0     0.0     1.8    1.2]
PrivE  [0.0   0.0    0.0    0.0    0.0      0.0     1.8     1.2     2.0    0.0]
Later  [0.8   0.0    0.0    1.0    1.0      0.0     0.0     1.5     0.0    0.0]
Exfil  [0.0   0.0    0.0    0.0    0.0      0.0     0.0     0.0     0.0    0.0]
Pers   [0.0   0.0    0.0    0.0    0.0      0.0     0.0     0.0     0.0    1.5]
C2     [0.0   0.0    0.0    0.0    0.0      0.0     1.5     1.8     0.0    0.0]
```

(Approximate initial seeded values. Exact values in `edges.rs::seed_mitre_weights()`.)

**Hebbian update rule:**

When action A is observed followed by action B from the same source within the co-occurrence window (default 1 hour):

```
weight[A][B] += learning_rate * activation_a * activation_b
```

Where `learning_rate` is 0.05, `activation` is the confidence of each observation (0.0-1.0), and weight is capped at `max_weight` (10.0).

**Temporal decay:**

Every `decay_interval` learn cycles (default 10):

```
for all edges:
  weight *= decay_rate  (default 0.995, i.e., 0.5% reduction)
  if weight < min_weight (0.001): weight = 0.0
```

Decay prevents stale attack patterns from dominating. If an attack path stops being observed, its edges fade toward zero. Active paths are reinforced faster than decay erodes them.

**Chain detection:**

The `patterns.rs` module defines 10 known attack chains (see README for the list). Each chain is a sequence of `ActionType` values with a minimum match count and a severity rating.

Matching uses subsequence search: the observed action sequence from a source is checked against each pattern. The observed actions must appear in the pattern's order but need not be contiguous. A `min_match` threshold allows partial matching (e.g., 4 of 6 steps for the full kill chain).

Chain threat contribution is computed as:

```
threat_contribution = match_ratio * severity_multiplier * chain_strength
```

Where `chain_strength` comes from the Hebbian edge weights along the matched path. Stronger edges (from repeated observation) amplify the threat score.

### Stage 5: Response

`ResponseOrchestrator` receives a source IP, its `ThreatScore`, and a reason string. It constructs response actions based on configuration:

1. **LogAlert** (always) -- Writes a JSON line to the alert log
2. **BlockIp** (if `blocking_enabled`) -- Calls `blocker::block_ip()`
3. **WebhookAlert** (if `webhook_url` configured) -- POST to URL
4. **EmailAlert** (if `alert_email` configured) -- Writes .eml to queue

Each action is logged with success/failure status. Failures in any channel (webhook timeout, firewall permission denied) are logged but don't crash the daemon or prevent other actions from executing.

Block deduplication prevents the same IP from being blocked twice. The orchestrator maintains an in-memory history of all actions taken.

## Hebbian Graph Deep Dive

### Why Hebbian Learning

Traditional security tools use static rules. If the attacker changes the order of operations, the rule misses.

Hebbian learning adapts. The graph starts with MITRE-seeded edges that encode known attack progressions. But if SENTINEL observes a novel progression -- say, credential attacks preceding vulnerability scans instead of the other way around -- that edge strengthens. Future attacks using that progression score higher.

The graph is not neural network inference. It's a 10x10 float matrix with multiply-accumulate operations. Edge updates take nanoseconds. The entire graph serializes to a few kilobytes of JSON.

### MITRE Mapping

The 10 graph nodes correspond to observable stages of the MITRE ATT&CK framework:

| Node | Index | MITRE Tactics | Stage Weight |
|------|-------|--------------|-------------|
| Reconnaissance | 0 | TA0043 | 0.10 |
| Enumeration | 1 | TA0043 | 0.15 |
| VulnerabilityScan | 2 | T1595.002 | 0.25 |
| CredentialAttack | 3 | T1110 | 0.40 |
| Exploitation | 4 | TA0001, TA0002 | 0.70 |
| PrivilegeEscalation | 5 | TA0004 | 0.80 |
| LateralMovement | 6 | TA0008 | 0.85 |
| DataExfiltration | 7 | TA0010 | 0.95 |
| Persistence | 8 | TA0003 | 0.90 |
| CommandControl | 9 | TA0011 | 0.90 |

Stage weights reflect inherent severity: recon is low-threat, data exfiltration is near-maximum. These weights contribute to the graph's threat score calculation independently of edge strengths.

### Graph Threat Score Composition

For a given source IP, the graph computes a threat score from four components:

```
raw_score = chain_score * 0.4     (matched attack patterns)
          + path_strength * 0.25  (Hebbian edge weights along observed path)
          + max_stage * 0.2       (highest kill-chain stage reached)
          + diversity * 0.15      (fraction of action types observed)
```

This means a source that matches a Critical pattern, has strong learned edges, reached a late kill-chain stage, and exhibited diverse action types scores near 1.0.

## Detection Algorithms

### Velocity: Sliding Window

The velocity scorer counts events within a configurable time window. The implementation:

1. Filter the session's events to those within `velocity_window_secs` of the most recent event
2. Count them
3. Divide by `velocity_saturation`
4. Clamp to [0.0, 1.0]

Default: 100 events in 60 seconds saturates to 1.0.

An additional `calculate_burst_velocity` function exists in the code for detecting short bursts (e.g., 10 events in 2 seconds). It is implemented but not wired into the main scoring pipeline. A contributor could integrate it by calling it in `rescore_sessions()` and incorporating the result.

### Coverage: Target Normalization

Coverage measures breadth of probing. The scorer counts unique targets:

```
unique_targets = session.targeted_ports.len() + session.targeted_endpoints.len()
```

Divided by `coverage_saturation` (default 20) and clamped.

A weighted variant (`calculate_weighted_coverage_score`) exists that assigns different weights to sensitive ports (22, 3389, 3306, etc.) versus common web ports. It is implemented but not used in the default scoring path.

### Correlation: Gap Measurement

Correlation measures how quickly reconnaissance leads to exploitation from the same source. For each exploit event, the scorer finds the nearest preceding recon/probe event and computes the time gap.

- Below `correlation_min_gap_secs` (default 1): score 1.0 (instant pivot, clearly automated)
- Above `correlation_max_gap_secs` (default 300): score 0.0 (uncorrelated)
- Between: linear interpolation

The final correlation score is the average across all recon-to-exploit pairs in the session.

## How to Add a New Log Source

1. Create `src/log_sources/your_source.rs`

2. Implement the `LogSource` trait:

```rust
pub trait LogSource {
    fn source_type(&self) -> LogSourceType;
    fn parse_line(&self, line: &str) -> Option<DetectionEvent>;
}
```

3. Your parser receives one line at a time. Return `Some(DetectionEvent)` if it matches, `None` if it doesn't. Lines that return `None` are skipped at zero cost to the detection engine.

4. Map your events to `EventType` variants. If none of the existing types fit, consider whether the event maps to an existing type (most do) or if a new variant is justified. Adding a variant requires updating `lib.rs::EventType` and the `From<&EventType> for AttackPhase` impl.

5. Add your source's file paths to the config. In `lib.rs`, add a field to `LogSourcesConfig`:

```rust
pub your_source_paths: Vec<PathBuf>,
```

6. Register your source in `LogSourceRegistry::new()` in `log_sources/mod.rs`. Follow the pattern used by `AuthLogSource`, `WebLogSource`, and `SyslogSource`.

7. Write tests. At minimum:
   - A unit test that verifies each log line format you support is correctly parsed
   - A unit test that verifies lines without external IPs return `None`
   - An integration test that feeds your log lines through the full pipeline

## How to Add a New Attack Pattern

1. Open `src/graph/patterns.rs`

2. Add a new `AttackPattern` to the `known_patterns()` function:

```rust
AttackPattern {
    id: "YOUR-001".into(),
    name: "Your Pattern Name".into(),
    description: "What this pattern indicates (defense context)".into(),
    sequence: vec![
        ActionType::A,
        ActionType::B,
        ActionType::C,
    ],
    min_match: 2,  // How many steps must match
    severity: Severity::High,
    mitre_refs: vec![
        "T1234".into(),  // MITRE technique IDs
    ],
},
```

3. Choose `min_match` carefully. Setting it equal to `sequence.len()` requires an exact match. Setting it to `sequence.len() - 1` allows one step to be missing. Setting it to 2 is the minimum for any pattern.

4. The pattern will automatically be matched against all source IP observation sequences during chain detection. No other code changes needed.

5. Write a test:

```rust
#[test]
fn test_your_pattern_match() {
    let observed = vec![ActionType::A, ActionType::B, ActionType::C];
    let patterns = known_patterns();
    let your_pattern = patterns.iter().find(|p| p.id == "YOUR-001").unwrap();
    let score = your_pattern.match_score(&observed);
    assert!(score > 0.0);
}
```

6. Consider whether the pattern needs corresponding seed weights in `edges.rs::seed_mitre_weights()`. If the action transitions in your pattern don't already have seeded weights, add them so the graph recognizes the pattern from first deployment.

# Known Limitations (v0.1)

Honest accounting of what SENTINEL Shield does not yet handle well. These are engineering scope decisions, not bugs.

## Credential Spray vs Brute Force

SENTINEL cannot distinguish a credential spray from a brute force attack. Both produce `AuthFailure` events from the same source IP. The difference is that a spray tries one password across many usernames while brute force tries many passwords against one username. Since `target_endpoint` in auth log events does not carry the username, the detection engine sees identical event streams for both.

**Impact:** The Credential Spray pattern (CS-001) triggers on the same evidence as the Brute Force pattern (BF-001). An operator cannot tell which is happening from SENTINEL's output alone. Both get detected. Neither gets correctly labeled.

**Future:** Extracting the target username into `target_endpoint` during auth log parsing would let the coverage scorer differentiate. A spray would show high endpoint diversity (many usernames). A brute force would show low (one username, repeated).

## Dual EventType Enum

Two separate enums classify events: `EventType` in `lib.rs` (used by parsers and the detection engine) and `ActionType` in `graph/nodes.rs` (used by the Hebbian graph). A mapping function in `detection/mod.rs` bridges them.

**Impact:** Adding a new event classification requires updating both enums and the mapping. This is maintenance cost, not a correctness issue. The mapping is tested and the compiler catches missing arms.

**Why it exists:** The graph's `ActionType` is a coarser abstraction. Multiple `EventType` values map to the same `ActionType` (e.g., `AuthFailure`, `BruteForce`, and `CredentialStuffing` all map to `CredentialAttack`). Merging them would either bloat the graph with low-signal distinctions or lose parser-level precision. Neither is acceptable yet.

## Sub-Saturated Brute Force

A slow brute force attack that generates around 45 events in the velocity window (default saturation: 100) achieves a velocity score of ~0.45. With low coverage (single port, single endpoint) and no correlation signal, the combined score lands around 0.2-0.3 -- well below the default 0.7 threshold.

**Impact:** Slow, targeted brute force attacks against a single service do not trigger by default. The attacker needs to generate enough events to push velocity toward saturation, or the attack must be accompanied by reconnaissance or broad scanning that activates coverage or correlation.

**Mitigating factors:** The Hebbian graph's threat score contribution (capped at +0.15 boost) can push borderline cases over threshold if the graph has learned the pattern from prior attacks. Operators can lower `threat_threshold` or `velocity_saturation` for sensitive hosts.

**Future:** Graph-derived adaptive weights could shift scoring weight toward velocity for environments where slow brute force is the primary threat. The `compute_adaptive_weights` function exists but is not yet fully integrated into the main scoring path.

## Broad Scanners Below Threshold

A scanner that probes many ports and endpoints but does so slowly (low velocity) and without subsequent exploitation (no correlation) relies entirely on the coverage score. With default weights, coverage alone caps at 0.35 contribution. That is half the threshold.

**Impact:** Pure reconnaissance with no follow-up exploitation scores below threshold. SENTINEL detects the attack pattern but does not trigger a response.

**Design rationale:** This is partially intentional. Port scanning without exploitation is common and often benign (Shodan, Censys, internal audits). Setting coverage weight high enough to trigger on scanning alone would generate false positives from legitimate services.

**Mitigating factors:** The Hebbian graph boosts the score if the source's action sequence matches a known pattern (e.g., AS-001 Automated Scanner). As the graph accumulates observations of scan-then-exploit patterns, its threat contribution pushes scanners closer to threshold. Operators monitoring the alert log will see sub-threshold scan activity in the JSONL output even when no response fires.

**Future:** A configurable "scan-only" response mode (log but don't block at a lower threshold) would address this without compromising the false-positive rate of the primary threshold.

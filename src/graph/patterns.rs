// SENTINEL Shield - Hebbian Attack Pattern Graph
// patterns.rs - Known attack chain patterns from MITRE ATT&CK kill chain
//
// DEFENSE ONLY: These patterns describe OBSERVABLE sequences that
// indicate an attack in progress. They are used for DETECTION and
// threat scoring. They do not provide attack instructions.
//
// Copyright (c) 2026 CIPS Corps. All rights reserved.

use serde::{Deserialize, Serialize};

use crate::graph::nodes::ActionType;

/// Severity level of a recognized attack chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Informational -- may be normal behavior
    Low,
    /// Suspicious -- warrants monitoring
    Medium,
    /// Active threat -- likely attack in progress
    High,
    /// Critical -- immediate action required
    Critical,
}

impl Severity {
    /// Numeric multiplier for threat score calculation.
    pub fn multiplier(&self) -> f64 {
        match self {
            Severity::Low => 0.25,
            Severity::Medium => 0.5,
            Severity::High => 0.8,
            Severity::Critical => 1.0,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A known attack chain pattern.
///
/// Defines a sequence of action types that, when observed from a single
/// source, indicate a specific class of attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    /// Unique identifier for this pattern.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// What this pattern indicates (defense context only).
    pub description: String,
    /// The sequence of action types that define this pattern.
    /// Order matters: the actions must appear in this order (not necessarily
    /// contiguous, but temporally ordered).
    pub sequence: Vec<ActionType>,
    /// How many of the sequence actions must match (allows partial matching).
    /// A value of sequence.len() means exact match required.
    /// A value of sequence.len() - 1 allows one step to be missing.
    pub min_match: usize,
    /// Severity if this pattern is detected.
    pub severity: Severity,
    /// MITRE ATT&CK technique IDs referenced (for documentation only).
    pub mitre_refs: Vec<String>,
}

impl AttackPattern {
    /// Check if an observed action sequence matches this pattern.
    ///
    /// Uses subsequence matching: the observed sequence must contain
    /// at least `min_match` actions from `self.sequence` in the correct order.
    ///
    /// Returns the match ratio (0.0 to 1.0) -- 0.0 means no match,
    /// 1.0 means complete match.
    pub fn match_score(&self, observed: &[ActionType]) -> f64 {
        if self.sequence.is_empty() || observed.is_empty() {
            return 0.0;
        }

        // Count how many of the pattern's steps appear in order in the observed sequence
        let mut pattern_idx = 0;
        let mut matched = 0;

        for &obs_action in observed {
            if pattern_idx < self.sequence.len() && obs_action == self.sequence[pattern_idx] {
                matched += 1;
                pattern_idx += 1;
            }
        }

        let ratio = matched as f64 / self.sequence.len() as f64;

        if matched >= self.min_match {
            ratio
        } else {
            0.0
        }
    }

    /// Check if the observed sequence is a partial match (in progress).
    /// Returns true if the beginning of the pattern matches, even if
    /// the full min_match threshold isn't met yet.
    pub fn is_partial_match(&self, observed: &[ActionType]) -> bool {
        if self.sequence.is_empty() || observed.is_empty() {
            return false;
        }

        let mut pattern_idx = 0;
        let mut matched = 0;

        for &obs_action in observed {
            if pattern_idx < self.sequence.len() && obs_action == self.sequence[pattern_idx] {
                matched += 1;
                pattern_idx += 1;
            }
        }

        // At least 2 steps matched and we haven't hit full match yet
        matched >= 2 && matched < self.min_match
    }
}

/// A detected attack chain instance tied to a specific source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    /// Which pattern was matched.
    pub pattern_id: String,
    /// Human-readable pattern name.
    pub pattern_name: String,
    /// Source IP or identifier.
    pub source: String,
    /// Match ratio (0.0 to 1.0).
    pub match_ratio: f64,
    /// Severity level.
    pub severity: Severity,
    /// The specific actions that matched, in order.
    pub matched_actions: Vec<ActionType>,
    /// Whether the chain is complete or still in progress.
    pub in_progress: bool,
    /// Threat contribution from this chain (match_ratio * severity multiplier * chain strength).
    pub threat_contribution: f64,
}

/// Build the library of known attack patterns.
///
/// These are based on commonly observed attack progressions documented
/// in MITRE ATT&CK. Each pattern represents a DEFENSIVE detection
/// signature -- "if we see these actions in this order, it looks like X."
pub fn known_patterns() -> Vec<AttackPattern> {
    use ActionType::*;

    vec![
        // === FULL KILL CHAIN ===
        AttackPattern {
            id: "KC-001".into(),
            name: "Full Kill Chain".into(),
            description: "Complete attack progression from reconnaissance through data exfiltration. \
                          Indicates a sophisticated, methodical threat actor."
                .into(),
            sequence: vec![
                Reconnaissance,
                Enumeration,
                VulnerabilityScan,
                Exploitation,
                PrivilegeEscalation,
                DataExfiltration,
            ],
            min_match: 4,
            severity: Severity::Critical,
            mitre_refs: vec![
                "TA0043".into(), // Reconnaissance
                "TA0001".into(), // Initial Access
                "TA0004".into(), // Privilege Escalation
                "TA0010".into(), // Exfiltration
            ],
        },
        // === CREDENTIAL SPRAY ===
        AttackPattern {
            id: "CS-001".into(),
            name: "Credential Spray Attack".into(),
            description: "Enumeration followed by credential attacks. Common in automated \
                          spray-and-pray campaigns targeting exposed services."
                .into(),
            sequence: vec![Reconnaissance, Enumeration, CredentialAttack, Exploitation],
            min_match: 3,
            severity: Severity::High,
            mitre_refs: vec![
                "T1110".into(),    // Brute Force
                "T1110.003".into(), // Password Spraying
            ],
        },
        // === RANSOMWARE PROGRESSION ===
        AttackPattern {
            id: "RW-001".into(),
            name: "Ransomware Progression".into(),
            description: "Exploitation followed by privilege escalation and persistence. \
                          Classic ransomware deployment pattern: gain access, escalate, \
                          establish persistence for payload delivery."
                .into(),
            sequence: vec![
                Exploitation,
                PrivilegeEscalation,
                Persistence,
                LateralMovement,
            ],
            min_match: 3,
            severity: Severity::Critical,
            mitre_refs: vec![
                "T1486".into(), // Data Encrypted for Impact
                "TA0004".into(), // Privilege Escalation
                "TA0003".into(), // Persistence
            ],
        },
        // === APT LATERAL MOVEMENT ===
        AttackPattern {
            id: "LM-001".into(),
            name: "Lateral Movement Campaign".into(),
            description: "Post-exploitation lateral movement with C2 establishment. \
                          Indicates an attacker has already gained initial access and \
                          is expanding their footprint."
                .into(),
            sequence: vec![
                Exploitation,
                PrivilegeEscalation,
                LateralMovement,
                CommandControl,
            ],
            min_match: 3,
            severity: Severity::Critical,
            mitre_refs: vec![
                "TA0008".into(), // Lateral Movement
                "TA0011".into(), // Command and Control
                "T1021".into(),  // Remote Services
            ],
        },
        // === DATA THEFT ===
        AttackPattern {
            id: "DT-001".into(),
            name: "Data Theft via C2".into(),
            description: "Command and control channel established, followed by data exfiltration. \
                          The attacker has control and is extracting value."
                .into(),
            sequence: vec![CommandControl, DataExfiltration],
            min_match: 2,
            severity: Severity::Critical,
            mitre_refs: vec![
                "TA0011".into(), // Command and Control
                "TA0010".into(), // Exfiltration
                "T1041".into(),  // Exfiltration Over C2 Channel
            ],
        },
        // === AUTOMATED SCANNER ===
        AttackPattern {
            id: "AS-001".into(),
            name: "Automated Vulnerability Scanner".into(),
            description: "Rapid reconnaissance and vulnerability scanning. While potentially \
                          benign (authorized pen test), unsolicited scanning is a precursor \
                          to exploitation."
                .into(),
            sequence: vec![Reconnaissance, VulnerabilityScan, Enumeration],
            min_match: 2,
            severity: Severity::Medium,
            mitre_refs: vec![
                "T1595".into(),     // Active Scanning
                "T1595.002".into(), // Vulnerability Scanning
            ],
        },
        // === BRUTE FORCE CAMPAIGN ===
        AttackPattern {
            id: "BF-001".into(),
            name: "Sustained Brute Force".into(),
            description: "Prolonged credential attacks, potentially with enumeration to \
                          discover valid usernames first. High volume, low sophistication."
                .into(),
            sequence: vec![Enumeration, CredentialAttack, CredentialAttack],
            min_match: 2,
            severity: Severity::High,
            mitre_refs: vec![
                "T1110.001".into(), // Password Guessing
                "T1110.004".into(), // Credential Stuffing
            ],
        },
        // === SUPPLY CHAIN / PERSISTENCE ===
        AttackPattern {
            id: "SC-001".into(),
            name: "Persistence Establishment".into(),
            description: "Exploitation followed immediately by persistence mechanisms. \
                          The attacker's first priority after access is ensuring they \
                          can return."
                .into(),
            sequence: vec![Exploitation, Persistence, CommandControl],
            min_match: 2,
            severity: Severity::High,
            mitre_refs: vec![
                "TA0003".into(), // Persistence
                "T1053".into(),  // Scheduled Task/Job
                "T1547".into(),  // Boot or Logon Autostart Execution
            ],
        },
        // === PIVOT AND EXFIL ===
        AttackPattern {
            id: "PE-001".into(),
            name: "Pivot and Exfiltrate".into(),
            description: "Lateral movement used to reach high-value targets, followed \
                          by data exfiltration. Indicates targeted data theft."
                .into(),
            sequence: vec![
                LateralMovement,
                Reconnaissance,
                PrivilegeEscalation,
                DataExfiltration,
            ],
            min_match: 3,
            severity: Severity::Critical,
            mitre_refs: vec![
                "TA0008".into(), // Lateral Movement
                "TA0010".into(), // Exfiltration
                "T1048".into(),  // Exfiltration Over Alternative Protocol
            ],
        },
        // === INITIAL ACCESS PROBE ===
        AttackPattern {
            id: "IA-001".into(),
            name: "Initial Access Probe".into(),
            description: "Low-severity reconnaissance activity. May be benign network \
                          scanning or the first stage of a multi-day attack."
                .into(),
            sequence: vec![Reconnaissance, Enumeration],
            min_match: 2,
            severity: Severity::Low,
            mitre_refs: vec![
                "T1595.001".into(), // Scanning IP Blocks
                "T1592".into(),     // Gather Victim Host Information
            ],
        },
    ]
}

/// Match observed actions against all known patterns.
///
/// Returns all matching chains sorted by severity (critical first),
/// including partial matches flagged as in_progress.
pub fn detect_chains(
    source: &str,
    observed: &[ActionType],
    edge_strengths: &dyn Fn(&[ActionType]) -> f64,
) -> Vec<AttackChain> {
    let patterns = known_patterns();
    let mut chains = Vec::new();

    for pattern in &patterns {
        let score = pattern.match_score(observed);
        let is_partial = pattern.is_partial_match(observed);

        if score > 0.0 || is_partial {
            // Collect matched actions
            let mut matched_actions = Vec::new();
            let mut pattern_idx = 0;
            for &obs in observed {
                if pattern_idx < pattern.sequence.len() && obs == pattern.sequence[pattern_idx] {
                    matched_actions.push(obs);
                    pattern_idx += 1;
                }
            }

            let match_ratio = if score > 0.0 {
                score
            } else {
                matched_actions.len() as f64 / pattern.sequence.len() as f64
            };

            // Calculate chain strength from the Hebbian edge weights
            let chain_weight = if matched_actions.len() >= 2 {
                edge_strengths(&matched_actions)
            } else {
                0.1
            };

            let threat_contribution =
                match_ratio * pattern.severity.multiplier() * chain_weight;

            chains.push(AttackChain {
                pattern_id: pattern.id.clone(),
                pattern_name: pattern.name.clone(),
                source: source.to_string(),
                match_ratio,
                severity: pattern.severity,
                matched_actions,
                in_progress: is_partial && score == 0.0,
                threat_contribution,
            });
        }
    }

    // Sort by severity descending, then by threat_contribution descending
    chains.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.threat_contribution.partial_cmp(&a.threat_contribution).unwrap_or(std::cmp::Ordering::Equal))
    });

    chains
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::nodes::ActionType::*;

    #[test]
    fn test_known_patterns_not_empty() {
        let patterns = known_patterns();
        assert!(!patterns.is_empty());
        // Every pattern should have at least 2 steps
        for p in &patterns {
            assert!(p.sequence.len() >= 2, "Pattern {} has < 2 steps", p.id);
            assert!(p.min_match >= 2, "Pattern {} min_match < 2", p.id);
            assert!(p.min_match <= p.sequence.len(), "Pattern {} min_match > sequence length", p.id);
        }
    }

    #[test]
    fn test_full_kill_chain_match() {
        let observed = vec![
            Reconnaissance,
            Enumeration,
            VulnerabilityScan,
            Exploitation,
            PrivilegeEscalation,
            DataExfiltration,
        ];
        let patterns = known_patterns();
        let kc = patterns.iter().find(|p| p.id == "KC-001").unwrap();
        let score = kc.match_score(&observed);
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_partial_kill_chain() {
        let observed = vec![Reconnaissance, Enumeration, VulnerabilityScan];
        let patterns = known_patterns();
        let kc = patterns.iter().find(|p| p.id == "KC-001").unwrap();
        // 3 out of 6 matched, min_match is 4 -- shouldn't be a full match
        let score = kc.match_score(&observed);
        assert_eq!(score, 0.0);
        // But should be a partial match
        assert!(kc.is_partial_match(&observed));
    }

    #[test]
    fn test_credential_spray_match() {
        let observed = vec![Reconnaissance, Enumeration, CredentialAttack];
        let patterns = known_patterns();
        let cs = patterns.iter().find(|p| p.id == "CS-001").unwrap();
        let score = cs.match_score(&observed);
        assert!(score > 0.0);
    }

    #[test]
    fn test_detect_chains_sorts_by_severity() {
        let observed = vec![
            Reconnaissance,
            Enumeration,
            VulnerabilityScan,
            Exploitation,
            PrivilegeEscalation,
            DataExfiltration,
        ];

        let chains = detect_chains("10.0.0.1", &observed, &|_actions| 1.0);
        assert!(!chains.is_empty());

        // Should be sorted: Critical first
        for window in chains.windows(2) {
            assert!(window[0].severity >= window[1].severity);
        }
    }

    #[test]
    fn test_no_match_for_unrelated_actions() {
        let observed = vec![DataExfiltration, Reconnaissance];
        let patterns = known_patterns();
        let kc = patterns.iter().find(|p| p.id == "KC-001").unwrap();
        // Order matters: exfil then recon doesn't match the kill chain
        let score = kc.match_score(&observed);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }
}

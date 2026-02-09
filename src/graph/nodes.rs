// SENTINEL Shield - Hebbian Attack Pattern Graph
// nodes.rs - Attack action type nodes
//
// DEFENSE ONLY: These nodes represent OBSERVABLE action categories
// used to DETECT attack patterns. They do not encode how to attack.
//
// Copyright (c) 2026 CIPS Corps. All rights reserved.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Categories of observable network/host actions.
///
/// Each variant maps to a class of behavior that, in isolation,
/// may be benign. The graph's job is to detect when sequences
/// of these actions form known or novel attack chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionType {
    /// Port scanning, service discovery, OS fingerprinting
    Reconnaissance,
    /// Directory listing, user enumeration, version detection
    Enumeration,
    /// CVE probing, known exploit attempt signatures
    VulnerabilityScan,
    /// Brute force, credential stuffing, default credential attempts
    CredentialAttack,
    /// Buffer overflow signatures, injection patterns, RCE attempts
    Exploitation,
    /// Sudo exploits, SUID abuse, token manipulation patterns
    PrivilegeEscalation,
    /// Internal scanning, pass-the-hash, remote execution from compromised host
    LateralMovement,
    /// Bulk data transfer, DNS tunneling, encoded outbound traffic
    DataExfiltration,
    /// Backdoor installation, scheduled task creation, registry modification
    Persistence,
    /// C2 beacon patterns, unusual outbound connection cadence
    CommandControl,
}

impl ActionType {
    /// All action types in kill-chain order (early to late stage).
    pub const ALL: [ActionType; 10] = [
        ActionType::Reconnaissance,
        ActionType::Enumeration,
        ActionType::VulnerabilityScan,
        ActionType::CredentialAttack,
        ActionType::Exploitation,
        ActionType::PrivilegeEscalation,
        ActionType::LateralMovement,
        ActionType::DataExfiltration,
        ActionType::Persistence,
        ActionType::CommandControl,
    ];

    /// Numeric index for adjacency matrix addressing.
    pub fn index(&self) -> usize {
        match self {
            ActionType::Reconnaissance => 0,
            ActionType::Enumeration => 1,
            ActionType::VulnerabilityScan => 2,
            ActionType::CredentialAttack => 3,
            ActionType::Exploitation => 4,
            ActionType::PrivilegeEscalation => 5,
            ActionType::LateralMovement => 6,
            ActionType::DataExfiltration => 7,
            ActionType::Persistence => 8,
            ActionType::CommandControl => 9,
        }
    }

    /// Reconstruct from index.
    pub fn from_index(idx: usize) -> Option<ActionType> {
        if idx < ActionType::ALL.len() {
            Some(ActionType::ALL[idx])
        } else {
            None
        }
    }

    /// Number of distinct action types.
    pub const COUNT: usize = 10;

    /// Kill-chain stage weight: later stages are inherently more threatening.
    /// Used as a multiplier in threat scoring.
    pub fn stage_weight(&self) -> f64 {
        match self {
            ActionType::Reconnaissance => 0.1,
            ActionType::Enumeration => 0.15,
            ActionType::VulnerabilityScan => 0.25,
            ActionType::CredentialAttack => 0.4,
            ActionType::Exploitation => 0.7,
            ActionType::PrivilegeEscalation => 0.8,
            ActionType::LateralMovement => 0.85,
            ActionType::DataExfiltration => 0.95,
            ActionType::Persistence => 0.9,
            ActionType::CommandControl => 0.9,
        }
    }
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ActionType::Reconnaissance => "Reconnaissance",
            ActionType::Enumeration => "Enumeration",
            ActionType::VulnerabilityScan => "VulnerabilityScan",
            ActionType::CredentialAttack => "CredentialAttack",
            ActionType::Exploitation => "Exploitation",
            ActionType::PrivilegeEscalation => "PrivilegeEscalation",
            ActionType::LateralMovement => "LateralMovement",
            ActionType::DataExfiltration => "DataExfiltration",
            ActionType::Persistence => "Persistence",
            ActionType::CommandControl => "CommandControl",
        };
        write!(f, "{}", name)
    }
}

/// A single observed action from a source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// Source IP address or identifier
    pub source: String,
    /// What type of action was observed
    pub action: ActionType,
    /// When it was observed
    pub timestamp: DateTime<Utc>,
    /// Activation strength (0.0-1.0). Represents confidence in classification.
    /// A definite port scan is 1.0; an ambiguous request might be 0.3.
    pub activation: f64,
}

impl Observation {
    pub fn new(source: String, action: ActionType, timestamp: DateTime<Utc>, activation: f64) -> Self {
        Self {
            source,
            action,
            timestamp,
            activation: activation.clamp(0.0, 1.0),
        }
    }
}

/// Per-source tracking of recent observations for chain building.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceTracker {
    /// The source IP or identifier
    pub source: String,
    /// Ordered list of recent observations (oldest first)
    pub observations: Vec<Observation>,
    /// Current accumulated threat score
    pub threat_score: f64,
    /// When this source was first seen
    pub first_seen: DateTime<Utc>,
    /// When this source was last seen
    pub last_seen: DateTime<Utc>,
}

impl SourceTracker {
    pub fn new(source: String, first_obs: &Observation) -> Self {
        Self {
            source,
            observations: vec![first_obs.clone()],
            threat_score: 0.0,
            first_seen: first_obs.timestamp,
            last_seen: first_obs.timestamp,
        }
    }

    /// Add an observation to this source's history.
    pub fn add_observation(&mut self, obs: Observation) {
        if obs.timestamp > self.last_seen {
            self.last_seen = obs.timestamp;
        }
        if obs.timestamp < self.first_seen {
            self.first_seen = obs.timestamp;
        }
        self.observations.push(obs);
    }

    /// Prune observations older than the given window.
    pub fn prune_before(&mut self, cutoff: DateTime<Utc>) {
        self.observations.retain(|o| o.timestamp >= cutoff);
    }

    /// Get the sequence of action types observed, in chronological order.
    pub fn action_sequence(&self) -> Vec<ActionType> {
        let mut sorted = self.observations.clone();
        sorted.sort_by_key(|o| o.timestamp);
        sorted.iter().map(|o| o.action).collect()
    }

    /// Get the unique action types observed (deduplicated, in order of first appearance).
    pub fn unique_action_sequence(&self) -> Vec<ActionType> {
        let mut seen = std::collections::HashSet::new();
        let mut sorted = self.observations.clone();
        sorted.sort_by_key(|o| o.timestamp);
        sorted
            .iter()
            .filter_map(|o| {
                if seen.insert(o.action) {
                    Some(o.action)
                } else {
                    None
                }
            })
            .collect()
    }

    /// How many distinct action types have been observed from this source.
    pub fn distinct_action_count(&self) -> usize {
        let mut types = std::collections::HashSet::new();
        for obs in &self.observations {
            types.insert(obs.action);
        }
        types.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type_roundtrip() {
        for action in ActionType::ALL.iter() {
            let idx = action.index();
            let recovered = ActionType::from_index(idx).unwrap();
            assert_eq!(*action, recovered);
        }
    }

    #[test]
    fn test_action_type_count() {
        assert_eq!(ActionType::ALL.len(), ActionType::COUNT);
    }

    #[test]
    fn test_stage_weights_monotonic_early() {
        // Early kill-chain stages should have lower weights
        assert!(ActionType::Reconnaissance.stage_weight() < ActionType::Exploitation.stage_weight());
        assert!(ActionType::Exploitation.stage_weight() < ActionType::DataExfiltration.stage_weight());
    }

    #[test]
    fn test_observation_activation_clamping() {
        let obs = Observation::new("1.2.3.4".into(), ActionType::Reconnaissance, Utc::now(), 1.5);
        assert_eq!(obs.activation, 1.0);

        let obs2 = Observation::new("1.2.3.4".into(), ActionType::Reconnaissance, Utc::now(), -0.3);
        assert_eq!(obs2.activation, 0.0);
    }

    #[test]
    fn test_source_tracker_sequence() {
        let now = Utc::now();
        let obs1 = Observation::new("10.0.0.1".into(), ActionType::Reconnaissance, now, 0.9);
        let mut tracker = SourceTracker::new("10.0.0.1".into(), &obs1);

        let obs2 = Observation::new(
            "10.0.0.1".into(),
            ActionType::Enumeration,
            now + chrono::Duration::seconds(10),
            0.8,
        );
        tracker.add_observation(obs2);

        let seq = tracker.action_sequence();
        assert_eq!(seq, vec![ActionType::Reconnaissance, ActionType::Enumeration]);
        assert_eq!(tracker.distinct_action_count(), 2);
    }
}

// SENTINEL Shield - Hebbian Attack Pattern Graph
// mod.rs - Module exports and AttackGraph struct (the main interface)
//
// DEFENSE ONLY: This module detects attack patterns through Hebbian
// learning on observed action sequences. It does not generate attacks
// or provide offensive capabilities.
//
// Copyright (c) 2026 CIPS Corps. All rights reserved.

pub mod edges;
pub mod nodes;
pub mod patterns;

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use edges::{EdgeMatrix, HebbianParams};
use nodes::{ActionType, Observation, SourceTracker};
use patterns::{detect_chains, AttackChain, Severity};

use crate::AttackPhase;

/// Configuration for the AttackGraph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphConfig {
    /// Hebbian learning parameters for the edge matrix.
    pub hebbian_params: HebbianParams,

    /// Time window (in seconds) within which two actions from the same source
    /// are considered temporally co-occurring for Hebbian learning.
    /// Default: 3600 (1 hour)
    pub co_occurrence_window_secs: i64,

    /// How long to retain observations before pruning (in seconds).
    /// Default: 86400 (24 hours)
    pub observation_retention_secs: i64,

    /// Minimum number of distinct action types from a source before
    /// chain detection is triggered.
    /// Default: 2
    pub min_actions_for_chain: usize,

    /// How many decay cycles between automatic decays.
    /// Decay is applied every `decay_interval` calls to `learn()`.
    /// Default: 10
    pub decay_interval: u64,

    /// Threat score threshold for alerts.
    /// Default: 0.5
    pub alert_threshold: f64,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            hebbian_params: HebbianParams::default(),
            co_occurrence_window_secs: 3600,
            observation_retention_secs: 86400,
            min_actions_for_chain: 2,
            decay_interval: 10,
            alert_threshold: 0.5,
        }
    }
}

/// The main Hebbian attack pattern graph.
///
/// Tracks observations from network sources, learns temporal co-occurrence
/// patterns via Hebbian edge strengthening, and detects known and novel
/// attack chains.
///
/// This is a DETECTION system. It observes and scores. It does not
/// generate, suggest, or facilitate attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraph {
    /// The edge weight matrix (Hebbian learned).
    pub edges: EdgeMatrix,

    /// Per-source observation tracking.
    pub sources: HashMap<String, SourceTracker>,

    /// Pending observation pairs for the next Hebbian update.
    /// Each entry is (from_action, to_action, activation_a, activation_b).
    pending_updates: Vec<(ActionType, ActionType, f64, f64)>,

    /// Configuration.
    pub config: GraphConfig,

    /// How many learn() calls since last decay.
    learn_cycles: u64,

    /// Total observations processed.
    pub total_observations: u64,

    /// Total chains detected across all time.
    pub total_chains_detected: u64,
}

impl AttackGraph {
    /// Create a new AttackGraph with MITRE-seeded weights and default config.
    pub fn new() -> Self {
        Self::with_config(GraphConfig::default())
    }

    /// Create a new AttackGraph with custom configuration.
    pub fn with_config(config: GraphConfig) -> Self {
        Self {
            edges: EdgeMatrix::new_seeded(config.hebbian_params.clone()),
            sources: HashMap::new(),
            pending_updates: Vec::new(),
            config,
            learn_cycles: 0,
            total_observations: 0,
            total_chains_detected: 0,
        }
    }

    /// Record an observed action from a source.
    ///
    /// This is the primary input method. When the detection engine
    /// classifies a network event as a particular action type, it
    /// calls this method with the source IP, action type, and timestamp.
    ///
    /// The observation is recorded in the source tracker, and if a
    /// previous action from the same source exists within the
    /// co-occurrence window, a Hebbian update pair is queued.
    pub fn add_observation(
        &mut self,
        source_ip: &str,
        action_type: ActionType,
        timestamp: DateTime<Utc>,
    ) {
        self.add_observation_with_activation(source_ip, action_type, timestamp, 1.0);
    }

    /// Record an observed action with explicit activation strength.
    ///
    /// Activation represents confidence in the classification (0.0-1.0).
    /// A definitive port scan is 1.0; an ambiguous request that might
    /// be normal traffic would be 0.3.
    pub fn add_observation_with_activation(
        &mut self,
        source_ip: &str,
        action_type: ActionType,
        timestamp: DateTime<Utc>,
        activation: f64,
    ) {
        let obs = Observation::new(source_ip.to_string(), action_type, timestamp, activation);
        self.total_observations += 1;

        let tracker = self
            .sources
            .entry(source_ip.to_string())
            .or_insert_with(|| SourceTracker::new(source_ip.to_string(), &obs));

        // If the tracker already exists, find temporal co-occurrences with
        // previous observations within the time window.
        let window = Duration::seconds(self.config.co_occurrence_window_secs);
        let cutoff = timestamp - window;

        // Queue Hebbian updates for each recent preceding action
        for prev_obs in tracker.observations.iter().rev() {
            if prev_obs.timestamp < cutoff {
                break; // Observations are mostly chronological; past the window
            }
            if prev_obs.timestamp < timestamp && prev_obs.action != action_type {
                self.pending_updates.push((
                    prev_obs.action,
                    action_type,
                    prev_obs.activation,
                    activation,
                ));
            }
        }

        // Add to tracker (after we've iterated previous observations)
        if tracker.observations.is_empty()
            || tracker.observations.last().map(|o| &o.source) != Some(&obs.source)
            || !tracker.observations.is_empty()
        {
            tracker.add_observation(obs);
        }
    }

    /// Run Hebbian learning on all pending observation pairs.
    ///
    /// This processes all queued co-occurrence pairs and strengthens
    /// the corresponding edges. Call this periodically (e.g., every
    /// N observations or on a timer).
    ///
    /// Also applies decay every `config.decay_interval` learn cycles.
    pub fn learn(&mut self) {
        // Apply all pending Hebbian updates
        for (from, to, act_a, act_b) in self.pending_updates.drain(..) {
            self.edges.strengthen(from, to, act_a, act_b);
        }

        self.learn_cycles += 1;

        // Periodic decay
        if self.learn_cycles.is_multiple_of(self.config.decay_interval) {
            self.decay();
        }
    }

    /// Apply temporal decay to all edge weights.
    ///
    /// This can be called explicitly or happens automatically
    /// via `learn()` at the configured interval.
    pub fn decay(&mut self) {
        self.edges.decay();
    }

    /// Calculate the threat score for a specific source IP.
    ///
    /// Returns a value from 0.0 (no threat) to 1.0 (maximum threat).
    ///
    /// The score is computed from:
    /// 1. Number and severity of matched attack chains
    /// 2. Edge weights along the observed action sequence
    /// 3. Kill-chain stage weights of observed actions
    /// 4. Diversity of action types (more diverse = more suspicious)
    pub fn get_threat_score(&self, source_ip: &str) -> f64 {
        let tracker = match self.sources.get(source_ip) {
            Some(t) => t,
            None => return 0.0,
        };

        if tracker.observations.is_empty() {
            return 0.0;
        }

        let observed = tracker.unique_action_sequence();

        if observed.len() < self.config.min_actions_for_chain {
            // Not enough actions for meaningful scoring.
            // Return a base score from the stage weight of the single action.
            return observed
                .first()
                .map(|a| a.stage_weight() * 0.1)
                .unwrap_or(0.0);
        }

        // Component 1: Chain detection score
        let chains = self.detect_chains_for_source(source_ip);
        let chain_score: f64 = chains
            .iter()
            .map(|c| c.threat_contribution)
            .sum::<f64>()
            .min(1.0);

        // Component 2: Edge path strength along observed sequence
        let path_strength = self.edges.chain_strength(&observed);

        // Component 3: Kill-chain stage progression
        // Higher-stage actions are inherently more threatening
        let max_stage_weight = observed
            .iter()
            .map(|a| a.stage_weight())
            .fold(0.0_f64, f64::max);

        // Component 4: Action diversity bonus
        // More distinct action types from one source = more suspicious
        let diversity = tracker.distinct_action_count() as f64 / ActionType::COUNT as f64;

        // Weighted combination
        let raw_score = chain_score * 0.4
            + path_strength.min(1.0) * 0.25
            + max_stage_weight * 0.2
            + diversity * 0.15;

        // Clamp to [0.0, 1.0]
        raw_score.clamp(0.0, 1.0)
    }

    /// Get all active attack chains detected for a specific source.
    ///
    /// Returns matched patterns sorted by severity (critical first).
    pub fn get_active_chains(&self, source_ip: &str) -> Vec<AttackChain> {
        self.detect_chains_for_source(source_ip)
    }

    /// Internal: detect chains for a source using the current edge weights.
    fn detect_chains_for_source(&self, source_ip: &str) -> Vec<AttackChain> {
        let tracker = match self.sources.get(source_ip) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let observed = tracker.unique_action_sequence();

        if observed.len() < self.config.min_actions_for_chain {
            return Vec::new();
        }

        let edges = &self.edges;
        detect_chains(source_ip, &observed, &|actions: &[ActionType]| {
            edges.chain_strength(actions)
        })
    }

    /// Get all sources currently above the alert threshold.
    pub fn get_alerts(&self) -> Vec<(String, f64, Severity)> {
        let mut alerts: Vec<(String, f64, Severity)> = self
            .sources
            .keys()
            .filter_map(|source| {
                let score = self.get_threat_score(source);
                if score >= self.config.alert_threshold {
                    let chains = self.get_active_chains(source);
                    let max_severity = chains
                        .iter()
                        .map(|c| c.severity)
                        .max()
                        .unwrap_or(Severity::Medium);
                    Some((source.clone(), score, max_severity))
                } else {
                    None
                }
            })
            .collect();

        alerts.sort_by(|a, b| {
            b.2.cmp(&a.2)
                .then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
        });

        alerts
    }

    /// Prune old observations from all source trackers.
    ///
    /// Removes observations older than `config.observation_retention_secs`.
    /// Also removes sources with zero remaining observations.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(self.config.observation_retention_secs);

        // Prune observations from each source
        for tracker in self.sources.values_mut() {
            tracker.prune_before(cutoff);
        }

        // Remove sources with no remaining observations
        self.sources.retain(|_, tracker| !tracker.observations.is_empty());
    }

    /// Get summary statistics about the graph state.
    pub fn stats(&self) -> GraphStats {
        let active_edges = self.edges.active_edges(0.0).len();
        let total_possible_edges = ActionType::COUNT * ActionType::COUNT;

        GraphStats {
            total_observations: self.total_observations,
            active_sources: self.sources.len(),
            active_edges,
            total_possible_edges,
            edge_density: active_edges as f64 / total_possible_edges as f64,
            total_edge_weight: self.edges.total_weight(),
            learn_cycles: self.learn_cycles,
            decay_cycles: self.edges.total_decays,
            total_chains_detected: self.total_chains_detected,
            pending_updates: self.pending_updates.len(),
        }
    }

    /// Save the graph state to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), GraphError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| GraphError::Serialization(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| GraphError::Io(e.to_string()))?;
        Ok(())
    }

    /// Load graph state from a JSON file.
    pub fn load(path: &Path) -> Result<Self, GraphError> {
        let json = std::fs::read_to_string(path).map_err(|e| GraphError::Io(e.to_string()))?;
        let graph: AttackGraph =
            serde_json::from_str(&json).map_err(|e| GraphError::Serialization(e.to_string()))?;
        Ok(graph)
    }

    /// Get the edge weight between two action types.
    /// Useful for diagnostics and visualization.
    pub fn edge_weight(&self, from: ActionType, to: ActionType) -> f64 {
        self.edges.get(from, to)
    }

    /// Get the strongest predicted next actions given a current action type.
    pub fn predict_next(&self, current: ActionType, n: usize) -> Vec<(ActionType, f64)> {
        self.edges.strongest_successors(current, n)
    }
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGraph {
    /// Number of node types in the graph (for external reporting).
    pub fn node_count(&self) -> usize {
        ActionType::COUNT
    }

    /// Strengthen the edge between two attack phases.
    ///
    /// Bridge method for the detection engine, which works in terms of
    /// `AttackPhase` from the core types. Maps phases to graph ActionTypes
    /// and strengthens the Hebbian edge.
    pub fn strengthen_edge(&mut self, from: &AttackPhase, to: &AttackPhase) {
        if let (Some(from_action), Some(to_action)) = (
            Self::phase_to_action(from),
            Self::phase_to_action(to),
        ) {
            self.edges.strengthen(from_action, to_action, 1.0, 1.0);
        }
    }

    /// Map an AttackPhase (from lib.rs core types) to a graph ActionType.
    ///
    /// Some phases don't have a direct mapping (e.g., ResourceDevelopment
    /// is not directly observable). Returns None for unmappable phases.
    fn phase_to_action(phase: &AttackPhase) -> Option<ActionType> {
        match phase {
            AttackPhase::Reconnaissance => Some(ActionType::Reconnaissance),
            AttackPhase::Discovery => Some(ActionType::Enumeration),
            AttackPhase::CredentialAccess => Some(ActionType::CredentialAttack),
            AttackPhase::InitialAccess => Some(ActionType::Exploitation),
            AttackPhase::Execution => Some(ActionType::Exploitation),
            AttackPhase::PrivilegeEscalation => Some(ActionType::PrivilegeEscalation),
            AttackPhase::LateralMovement => Some(ActionType::LateralMovement),
            AttackPhase::Exfiltration => Some(ActionType::DataExfiltration),
            AttackPhase::Persistence => Some(ActionType::Persistence),
            AttackPhase::Collection => Some(ActionType::DataExfiltration),
            AttackPhase::DefenseEvasion => None, // No direct graph node
            AttackPhase::ResourceDevelopment => None, // Not observable from logs
        }
    }
}

/// Summary statistics about the graph state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub total_observations: u64,
    pub active_sources: usize,
    pub active_edges: usize,
    pub total_possible_edges: usize,
    pub edge_density: f64,
    pub total_edge_weight: f64,
    pub learn_cycles: u64,
    pub decay_cycles: u64,
    pub total_chains_detected: u64,
    pub pending_updates: usize,
}

/// Errors that can occur in graph operations.
#[derive(Debug, Clone)]
pub enum GraphError {
    Io(String),
    Serialization(String),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphError::Io(msg) => write!(f, "IO error: {}", msg),
            GraphError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for GraphError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_graph_has_seeded_weights() {
        let graph = AttackGraph::new();
        // MITRE seeded: recon -> enum should have weight
        assert!(graph.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration) > 0.0);
    }

    #[test]
    fn test_add_observation_creates_tracker() {
        let mut graph = AttackGraph::new();
        let now = Utc::now();
        graph.add_observation("192.168.1.100", ActionType::Reconnaissance, now);
        assert!(graph.sources.contains_key("192.168.1.100"));
        assert_eq!(graph.total_observations, 1);
    }

    #[test]
    fn test_threat_score_increases_with_attack_chain() {
        let mut graph = AttackGraph::new();
        let base = Utc::now();

        // Single recon action -- low threat
        graph.add_observation("10.0.0.50", ActionType::Reconnaissance, base);
        let score_after_recon = graph.get_threat_score("10.0.0.50");

        // Add enumeration -- threat should increase
        graph.add_observation(
            "10.0.0.50",
            ActionType::Enumeration,
            base + Duration::seconds(30),
        );
        graph.learn();
        let score_after_enum = graph.get_threat_score("10.0.0.50");
        assert!(
            score_after_enum > score_after_recon,
            "Score should increase: {} vs {}",
            score_after_enum,
            score_after_recon
        );

        // Add vuln scan + exploitation -- deeper into kill chain
        graph.add_observation(
            "10.0.0.50",
            ActionType::VulnerabilityScan,
            base + Duration::seconds(60),
        );
        graph.add_observation(
            "10.0.0.50",
            ActionType::Exploitation,
            base + Duration::seconds(90),
        );
        graph.learn();
        let score_after_exploit = graph.get_threat_score("10.0.0.50");

        // A 4-step attack chain (recon -> enum -> vuln scan -> exploit) should
        // score higher than a single recon observation.
        assert!(
            score_after_exploit > score_after_recon,
            "Full chain should score higher than single recon: {} vs {}",
            score_after_exploit,
            score_after_recon
        );
    }

    #[test]
    fn test_full_kill_chain_detection() {
        let mut graph = AttackGraph::new();
        let base = Utc::now();

        let actions = vec![
            ActionType::Reconnaissance,
            ActionType::Enumeration,
            ActionType::VulnerabilityScan,
            ActionType::Exploitation,
            ActionType::PrivilegeEscalation,
            ActionType::DataExfiltration,
        ];

        for (i, action) in actions.iter().enumerate() {
            graph.add_observation(
                "attacker.ip",
                *action,
                base + Duration::seconds(i as i64 * 60),
            );
        }
        graph.learn();

        let chains = graph.get_active_chains("attacker.ip");
        assert!(!chains.is_empty(), "Should detect at least one chain");

        // Should detect the full kill chain
        let kc = chains.iter().find(|c| c.pattern_id == "KC-001");
        assert!(kc.is_some(), "Should detect full kill chain pattern");
        assert_eq!(kc.unwrap().severity, Severity::Critical);

        // Threat score should be high
        let score = graph.get_threat_score("attacker.ip");
        assert!(score > 0.5, "Full kill chain should produce high threat score: {}", score);
    }

    #[test]
    fn test_benign_source_low_score() {
        let graph = AttackGraph::new();
        // No observations from this source
        assert_eq!(graph.get_threat_score("innocent.host"), 0.0);
    }

    #[test]
    fn test_hebbian_learning_strengthens_edges() {
        let mut graph = AttackGraph::new();
        let base = Utc::now();

        let initial_weight = graph.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration);

        // Observe recon -> enum several times from different sources
        for i in 0..5 {
            let src = format!("src_{}", i);
            graph.add_observation(&src, ActionType::Reconnaissance, base + Duration::seconds(i * 100));
            graph.add_observation(
                &src,
                ActionType::Enumeration,
                base + Duration::seconds(i * 100 + 30),
            );
        }
        graph.learn();

        let learned_weight = graph.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration);
        assert!(
            learned_weight > initial_weight,
            "Hebbian learning should strengthen observed co-occurrence: {} vs {}",
            learned_weight,
            initial_weight
        );
    }

    #[test]
    fn test_decay_weakens_edges() {
        let mut graph = AttackGraph::new();
        let before = graph.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration);

        graph.decay();

        let after = graph.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration);
        assert!(after < before);
    }

    #[test]
    fn test_prune_removes_old_observations() {
        let mut graph = AttackGraph::new();
        let old_time = Utc::now() - Duration::seconds(100_000);
        let recent_time = Utc::now();

        graph.add_observation("old.source", ActionType::Reconnaissance, old_time);
        graph.add_observation("recent.source", ActionType::Reconnaissance, recent_time);

        assert!(graph.sources.contains_key("old.source"));
        assert!(graph.sources.contains_key("recent.source"));

        graph.prune(Utc::now());

        // Old source should be pruned (default retention is 86400s)
        assert!(!graph.sources.contains_key("old.source"));
        assert!(graph.sources.contains_key("recent.source"));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let mut graph = AttackGraph::new();
        let base = Utc::now();
        graph.add_observation("10.0.0.1", ActionType::Reconnaissance, base);
        graph.add_observation(
            "10.0.0.1",
            ActionType::Enumeration,
            base + Duration::seconds(30),
        );
        graph.learn();

        let tmp = std::env::temp_dir().join("sentinel_test_graph.json");
        graph.save(&tmp).unwrap();

        let loaded = AttackGraph::load(&tmp).unwrap();
        assert_eq!(loaded.total_observations, graph.total_observations);
        assert_eq!(
            loaded.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration),
            graph.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration)
        );

        // Cleanup
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_stats() {
        let graph = AttackGraph::new();
        let stats = graph.stats();
        assert_eq!(stats.total_observations, 0);
        assert_eq!(stats.active_sources, 0);
        assert!(stats.active_edges > 0); // Seeded edges
        assert!(stats.edge_density > 0.0);
    }

    #[test]
    fn test_predict_next_returns_known_progressions() {
        let graph = AttackGraph::new();
        let predictions = graph.predict_next(ActionType::Reconnaissance, 3);
        assert!(!predictions.is_empty());

        // Enumeration should be among the top predictions after Recon
        let has_enum = predictions.iter().any(|(a, _)| *a == ActionType::Enumeration);
        assert!(has_enum, "Enumeration should be a predicted successor of Reconnaissance");
    }

    #[test]
    fn test_get_alerts() {
        let mut graph = AttackGraph::with_config(GraphConfig {
            alert_threshold: 0.3,
            ..Default::default()
        });
        let base = Utc::now();

        // Create a threatening sequence
        let actions = vec![
            ActionType::Reconnaissance,
            ActionType::Enumeration,
            ActionType::VulnerabilityScan,
            ActionType::Exploitation,
        ];

        for (i, action) in actions.iter().enumerate() {
            graph.add_observation(
                "bad.actor",
                *action,
                base + Duration::seconds(i as i64 * 30),
            );
        }
        graph.learn();

        let alerts = graph.get_alerts();
        let has_bad_actor = alerts.iter().any(|(src, _, _)| src == "bad.actor");
        assert!(has_bad_actor, "bad.actor should trigger an alert");
    }

    #[test]
    fn test_multiple_sources_independent() {
        let mut graph = AttackGraph::new();
        let base = Utc::now();

        // Source A: recon only
        graph.add_observation("source_a", ActionType::Reconnaissance, base);

        // Source B: full chain
        for (i, action) in [
            ActionType::Reconnaissance,
            ActionType::Exploitation,
            ActionType::DataExfiltration,
        ]
        .iter()
        .enumerate()
        {
            graph.add_observation("source_b", *action, base + Duration::seconds(i as i64 * 30));
        }
        graph.learn();

        let score_a = graph.get_threat_score("source_a");
        let score_b = graph.get_threat_score("source_b");

        assert!(
            score_b > score_a,
            "Source B (full chain) should have higher threat than source A (recon only): {} vs {}",
            score_b,
            score_a
        );
    }

    #[test]
    fn test_activation_strength_affects_learning() {
        let mut graph1 = AttackGraph::new();
        let mut graph2 = AttackGraph::new();
        let base = Utc::now();

        // Graph 1: high confidence observations
        graph1.add_observation_with_activation("src", ActionType::Reconnaissance, base, 1.0);
        graph1.add_observation_with_activation(
            "src",
            ActionType::Enumeration,
            base + Duration::seconds(30),
            1.0,
        );
        graph1.learn();

        // Graph 2: low confidence observations
        graph2.add_observation_with_activation("src", ActionType::Reconnaissance, base, 0.2);
        graph2.add_observation_with_activation(
            "src",
            ActionType::Enumeration,
            base + Duration::seconds(30),
            0.2,
        );
        graph2.learn();

        let w1 = graph1.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration);
        let w2 = graph2.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration);

        // Both should have increased from baseline, but graph1 more than graph2
        // (because activation * activation in the Hebbian formula)
        assert!(
            w1 > w2,
            "High confidence should strengthen more than low confidence: {} vs {}",
            w1,
            w2
        );
    }
}

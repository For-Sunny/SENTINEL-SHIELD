//! # Detection Engine Orchestrator
//!
//! The detection engine is the brain of SENTINEL Shield. It receives raw
//! `DetectionEvent`s from log sources, groups them into `AttackSession`s by
//! source IP, runs velocity/coverage/correlation analysis, and produces
//! `ThreatScore`s that drive response actions.
//!
//! The engine also feeds observed attack patterns into the Hebbian graph
//! so the system learns which attack phases tend to co-occur.

pub mod velocity;
pub mod coverage;
pub mod correlation;
pub mod scorer;

use std::collections::HashMap;
use std::net::IpAddr;

use crate::graph::AttackGraph;
use crate::graph::nodes::ActionType;
use crate::learning_control::LearningControl;
use crate::{
    AttackSession, DetectionConfig, DetectionEvent, EventType,
    ScoreWeights, ShieldResult, ThreatScore,
};

/// The detection engine. Maintains active sessions and orchestrates
/// the three detection sub-systems (velocity, coverage, correlation).
pub struct DetectionEngine {
    /// Configuration for detection thresholds and weights.
    config: DetectionConfig,

    /// Active attack sessions keyed by source IP.
    sessions: HashMap<IpAddr, AttackSession>,

    /// The Hebbian attack pattern graph.
    graph: AttackGraph,

    /// Score weights derived from config.
    weights: ScoreWeights,

    /// Runtime control valve for Hebbian graph learning.
    /// Operators can pause, resume, throttle, or adjust learning
    /// without stopping detection.
    learning_control: LearningControl,
}

impl DetectionEngine {
    /// Create a new detection engine with the given configuration and graph.
    pub fn new(config: &DetectionConfig, graph: AttackGraph) -> Self {
        let weights = ScoreWeights::from(config);
        Self {
            config: config.clone(),
            sessions: HashMap::new(),
            graph,
            weights,
            learning_control: LearningControl::new(),
        }
    }

    /// Process a batch of new detection events.
    ///
    /// Each event is assigned to a session (by source IP), then all affected
    /// sessions are re-scored. Events are also fed into the Hebbian graph
    /// via `add_observation()` so the graph accumulates knowledge about
    /// attack patterns. Returns sessions that exceed the threat threshold.
    pub fn process_events(&mut self, events: Vec<DetectionEvent>) -> ShieldResult<Vec<&AttackSession>> {
        for event in events {
            let ip = event.source_ip;

            // Feed event into the Hebbian graph so SourceTracker gets
            // populated and the graph can score per-source threats.
            if let Some(action) = Self::event_to_action(&event.event_type) {
                self.graph.add_observation(
                    &ip.to_string(),
                    action,
                    event.timestamp,
                );
            }

            if let Some(session) = self.sessions.get_mut(&ip) {
                session.add_event(event);
            } else {
                self.sessions.insert(ip, AttackSession::new(event));
            }
        }

        // Apply Hebbian learning on queued co-occurrence pairs AND
        // phase-transition edge strengthening, both gated by the
        // learning control valve. When an operator pauses learning,
        // NEITHER path modifies the edge matrix.
        if self.learning_control.should_learn() {
            let rate = self.learning_control.effective_rate();
            self.update_graph(rate);
            self.graph.learn_with_rate(rate);
        }

        // Re-score all sessions (now with graph knowledge)
        self.rescore_sessions();

        // Collect sessions exceeding threshold
        let threshold = self.config.threat_threshold;
        let threatening: Vec<&AttackSession> = self.sessions
            .values()
            .filter(|s| s.threat_score.is_threat(threshold))
            .collect();

        Ok(threatening)
    }

    /// Map an EventType to the graph's ActionType for observation feeding.
    ///
    /// Returns None for event types that don't map cleanly to a graph node.
    fn event_to_action(event_type: &EventType) -> Option<ActionType> {
        match event_type {
            EventType::Reconnaissance => Some(ActionType::Reconnaissance),
            EventType::WebProbe => Some(ActionType::Enumeration),
            EventType::AuthFailure => Some(ActionType::CredentialAttack),
            EventType::BruteForce => Some(ActionType::CredentialAttack),
            EventType::CredentialStuffing => Some(ActionType::CredentialAttack),
            EventType::AuthSuccess => Some(ActionType::Exploitation),
            EventType::ExploitAttempt => Some(ActionType::Exploitation),
            EventType::LateralMovement => Some(ActionType::LateralMovement),
            EventType::DataExfiltration => Some(ActionType::DataExfiltration),
            EventType::Suspicious => Some(ActionType::Reconnaissance),
        }
    }

    /// Re-score all active sessions using the three detection sub-systems
    /// plus graph-derived knowledge.
    ///
    /// The graph contributes in two ways:
    /// 1. **Adaptive weights** - `compute_adaptive_weights` shifts weight
    ///    toward whichever signal the graph has learned is most predictive.
    /// 2. **Graph threat boost** - if the graph's internal SourceTracker
    ///    has a non-zero threat score for this IP (from chain detection),
    ///    it boosts the combined score. This means the graph's accumulated
    ///    pattern knowledge feeds into real scoring decisions.
    fn rescore_sessions(&mut self) {
        let velocity_window = self.config.velocity_window_secs;
        let velocity_saturation = self.config.velocity_saturation;
        let coverage_saturation = self.config.coverage_saturation;
        let corr_min = self.config.correlation_min_gap_secs;
        let corr_max = self.config.correlation_max_gap_secs;

        // Compute adaptive weights from graph's learned edge patterns.
        // The graph knows which attack progressions are common in THIS
        // environment, so it shifts weight toward the most predictive signal.
        use crate::graph::nodes::ActionType;
        let recon_exploit_strength = self.graph.edge_weight(
            ActionType::Reconnaissance,
            ActionType::Exploitation,
        );
        let broad_scan_strength = self.graph.edge_weight(
            ActionType::Reconnaissance,
            ActionType::Enumeration,
        );
        let weights = scorer::compute_adaptive_weights(
            &self.weights,
            recon_exploit_strength,
            broad_scan_strength,
            0.3, // moderate adaptation rate
        );

        for session in self.sessions.values_mut() {
            let v = velocity::calculate_velocity_score(
                &session.events,
                velocity_window,
                velocity_saturation,
            );
            let c = coverage::calculate_coverage_score(
                session,
                coverage_saturation,
            );
            let r = correlation::calculate_correlation_score(
                &session.events,
                corr_min,
                corr_max,
            );

            // Query the graph's threat score for this source IP.
            // This incorporates chain detection, edge path strength,
            // kill-chain stage progression, and action diversity.
            let graph_score = self.graph.get_threat_score(&session.source_ip.to_string());

            // Blend graph knowledge into the final score.
            // The graph boost is additive: if the graph detects attack chains
            // that the velocity/coverage/correlation model misses, it pushes
            // the score upward. Capped at 0.15 to avoid the graph alone
            // causing false positives -- it's a boost, not a replacement.
            let mut score = ThreatScore::new(v, c, r, &weights);
            if graph_score > 0.0 {
                let graph_boost = (graph_score * 0.15).min(0.15);
                score.combined = (score.combined + graph_boost).clamp(0.0, 1.0);
            }

            session.threat_score = score;
        }
    }

    /// Update the Hebbian graph with patterns observed in current sessions.
    ///
    /// Only processes sessions where `phases_dirty` is true, meaning new
    /// phase transitions arrived since the last call. This avoids redundant
    /// `strengthen_edge` calls on unchanged sessions. With 500 sessions
    /// and 3 phases each, that eliminates ~1,000 wasted calls per batch.
    ///
    /// The `rate` parameter is the LearningControl effective rate, so
    /// edge strengthening respects the same valve as `learn_with_rate()`.
    fn update_graph(&mut self, rate: f64) {
        for session in self.sessions.values_mut() {
            if !session.phases_dirty {
                continue;
            }

            if session.attack_phases.len() >= 2 {
                // Feed sequential phase pairs into graph with rate control
                for window in session.attack_phases.windows(2) {
                    self.graph.strengthen_edge_with_rate(&window[0], &window[1], rate);
                }
            }

            session.phases_dirty = false;
        }
    }

    /// Get a reference to the attack graph.
    pub fn graph(&self) -> &AttackGraph {
        &self.graph
    }

    /// Get all active sessions.
    pub fn sessions(&self) -> &HashMap<IpAddr, AttackSession> {
        &self.sessions
    }

    /// Get mutable access to all active sessions.
    ///
    /// Used by the main loop to mark sessions as responded to, preventing
    /// duplicate response actions on subsequent poll cycles.
    pub fn sessions_mut(&mut self) -> &mut HashMap<IpAddr, AttackSession> {
        &mut self.sessions
    }

    /// Get a mutable reference to the attack graph.
    ///
    /// Used by the main loop for periodic maintenance (learn, decay, prune, save).
    pub fn graph_mut(&mut self) -> &mut AttackGraph {
        &mut self.graph
    }

    /// Get a reference to the learning control valve.
    pub fn learning_control(&self) -> &LearningControl {
        &self.learning_control
    }

    /// Get a mutable reference to the learning control valve.
    ///
    /// Used by the dashboard API and command interface to pause, resume,
    /// set rate, and adjust batch frequency at runtime.
    pub fn learning_control_mut(&mut self) -> &mut LearningControl {
        &mut self.learning_control
    }

    /// Remove stale sessions older than the given age in seconds.
    pub fn prune_sessions(&mut self, max_age_secs: i64) {
        let now = chrono::Utc::now();
        self.sessions.retain(|_ip, session| {
            (now - session.last_seen).num_seconds() < max_age_secs
        });
    }
}

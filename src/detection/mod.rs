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
use crate::{
    AttackSession, DetectionConfig, DetectionEvent, ScoreWeights, ShieldResult, ThreatScore,
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
        }
    }

    /// Process a batch of new detection events.
    ///
    /// Each event is assigned to a session (by source IP), then all affected
    /// sessions are re-scored. Returns a list of sessions that exceed the
    /// threat threshold after scoring.
    pub fn process_events(&mut self, events: Vec<DetectionEvent>) -> ShieldResult<Vec<&AttackSession>> {
        // For each event, find or create an AttackSession for the source IP,
        // add the event, re-score affected sessions, and return those exceeding threshold.

        for event in events {
            let ip = event.source_ip;

            if let Some(session) = self.sessions.get_mut(&ip) {
                // Session already exists for this IP -- add the new event.
                session.add_event(event);
            } else {
                // First event from this IP -- create a new session.
                // AttackSession::new() already stores the event in session.events,
                // so we must NOT call add_event() again for the initial event.
                self.sessions.insert(ip, AttackSession::new(event));
            }
        }

        // Re-score all sessions
        self.rescore_sessions();

        // Collect sessions exceeding threshold
        let threshold = self.config.threat_threshold;
        let threatening: Vec<&AttackSession> = self.sessions
            .values()
            .filter(|s| s.threat_score.is_threat(threshold))
            .collect();

        Ok(threatening)
    }

    /// Re-score all active sessions using the three detection sub-systems.
    fn rescore_sessions(&mut self) {
        let velocity_window = self.config.velocity_window_secs;
        let velocity_saturation = self.config.velocity_saturation;
        let coverage_saturation = self.config.coverage_saturation;
        let corr_min = self.config.correlation_min_gap_secs;
        let corr_max = self.config.correlation_max_gap_secs;
        let weights = self.weights;

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

            session.threat_score = ThreatScore::new(v, c, r, &weights);
        }
    }

    /// Update the Hebbian graph with patterns observed in current sessions.
    pub fn update_graph(&mut self) {
        // For each session, extract the sequence of attack phases
        // and feed co-occurring phases into the graph as edge activations.

        for session in self.sessions.values() {
            if session.attack_phases.len() >= 2 {
                // Feed sequential phase pairs into graph
                for window in session.attack_phases.windows(2) {
                    self.graph.strengthen_edge(&window[0], &window[1]);
                }
            }
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

    /// Remove stale sessions older than the given age in seconds.
    pub fn prune_sessions(&mut self, max_age_secs: i64) {
        let now = chrono::Utc::now();
        self.sessions.retain(|_ip, session| {
            (now - session.last_seen).num_seconds() < max_age_secs
        });
    }
}

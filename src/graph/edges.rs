// SENTINEL Shield - Hebbian Attack Pattern Graph
// edges.rs - Temporal co-occurrence edges with Hebbian learning
//
// DEFENSE ONLY: Edge weights represent how strongly action A
// PREDICTS action B in observed sequences. This is detection
// infrastructure, not attack generation.
//
// Copyright (c) 2026 CIPS Corps. All rights reserved.

use serde::{Deserialize, Serialize};

use crate::graph::nodes::ActionType;

/// The number of nodes in the graph. Fixed at compile time.
pub const NODE_COUNT: usize = ActionType::COUNT;

/// Hebbian learning parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HebbianParams {
    /// Learning rate: how much each co-occurrence strengthens an edge.
    /// Default: 0.05
    pub learning_rate: f64,

    /// Decay rate applied per decay cycle. Multiplied against all weights.
    /// Default: 0.995 (0.5% decay per cycle)
    pub decay_rate: f64,

    /// Maximum edge weight. Prevents runaway strengthening.
    /// Default: 10.0
    pub max_weight: f64,

    /// Minimum weight below which an edge is considered inactive.
    /// Default: 0.001
    pub min_weight: f64,
}

impl Default for HebbianParams {
    fn default() -> Self {
        Self {
            learning_rate: 0.05,
            decay_rate: 0.995,
            max_weight: 10.0,
            min_weight: 0.001,
        }
    }
}

/// Adjacency matrix of edge weights between action types.
///
/// `weights[i][j]` represents how strongly observing action i
/// predicts that action j will follow. This is a directed graph:
/// A->B does not imply B->A.
///
/// Hebbian rule: "Neurons that fire together wire together."
/// When action A is observed followed by action B from the same source,
/// the edge A->B is strengthened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeMatrix {
    /// The weight matrix. weights[from][to].
    pub weights: [[f64; NODE_COUNT]; NODE_COUNT],

    /// Total number of Hebbian updates applied.
    pub total_updates: u64,

    /// Total number of decay cycles applied.
    pub total_decays: u64,

    /// Learning parameters.
    pub params: HebbianParams,
}

impl EdgeMatrix {
    /// Create a new edge matrix with zero weights.
    pub fn new(params: HebbianParams) -> Self {
        Self {
            weights: [[0.0; NODE_COUNT]; NODE_COUNT],
            total_updates: 0,
            total_decays: 0,
            params,
        }
    }

    /// Create a new edge matrix seeded with MITRE ATT&CK common sequences.
    pub fn new_seeded(params: HebbianParams) -> Self {
        let mut matrix = Self::new(params);
        matrix.seed_mitre_weights();
        matrix
    }

    /// Get the weight of edge from -> to.
    pub fn get(&self, from: ActionType, to: ActionType) -> f64 {
        self.weights[from.index()][to.index()]
    }

    /// Set the weight of edge from -> to directly (used for seeding).
    pub fn set(&mut self, from: ActionType, to: ActionType, weight: f64) {
        self.weights[from.index()][to.index()] = weight.clamp(0.0, self.params.max_weight);
    }

    /// Hebbian strengthening: reinforce the edge from -> to.
    ///
    /// Formula: weight += learning_rate * activation_a * activation_b
    ///
    /// - activation_a: confidence that action A was observed (0.0-1.0)
    /// - activation_b: confidence that action B was observed (0.0-1.0)
    pub fn strengthen(&mut self, from: ActionType, to: ActionType, activation_a: f64, activation_b: f64) {
        self.strengthen_with_rate(from, to, activation_a, activation_b, 1.0);
    }

    /// Hebbian strengthening with an external rate multiplier.
    ///
    /// Formula: weight += learning_rate * rate * activation_a * activation_b
    ///
    /// The `rate` parameter is an external multiplier from the LearningControl
    /// valve. 1.0 = normal, 0.5 = half speed, 2.0 = double speed.
    pub fn strengthen_with_rate(
        &mut self,
        from: ActionType,
        to: ActionType,
        activation_a: f64,
        activation_b: f64,
        rate: f64,
    ) {
        let delta = self.params.learning_rate * rate * activation_a * activation_b;
        let i = from.index();
        let j = to.index();
        self.weights[i][j] = (self.weights[i][j] + delta).min(self.params.max_weight);
        self.total_updates += 1;
    }

    /// Apply temporal decay to ALL edges.
    ///
    /// Every edge weight is multiplied by decay_rate.
    /// Edges that drop below min_weight are zeroed out.
    /// This prevents stale patterns from persisting indefinitely.
    pub fn decay(&mut self) {
        for i in 0..NODE_COUNT {
            for j in 0..NODE_COUNT {
                self.weights[i][j] *= self.params.decay_rate;
                if self.weights[i][j] < self.params.min_weight {
                    self.weights[i][j] = 0.0;
                }
            }
        }
        self.total_decays += 1;
    }

    /// Calculate the path strength along a sequence of action types.
    ///
    /// Given [A, B, C], returns the product of weights(A->B) * weights(B->C),
    /// normalized. Returns 0.0 if any link in the chain is zero.
    pub fn chain_strength(&self, chain: &[ActionType]) -> f64 {
        if chain.len() < 2 {
            return 0.0;
        }

        let mut strength = 1.0;
        let mut has_nonzero = false;

        for window in chain.windows(2) {
            let w = self.get(window[0], window[1]);
            if w > 0.0 {
                has_nonzero = true;
                strength *= w;
            } else {
                return 0.0; // Chain is broken
            }
        }

        if !has_nonzero {
            return 0.0;
        }

        // Normalize by the number of edges in the chain
        let edges = (chain.len() - 1) as f64;
        strength.powf(1.0 / edges)
    }

    /// Get the strongest N successors for a given action type.
    /// Returns (ActionType, weight) pairs sorted by weight descending.
    pub fn strongest_successors(&self, from: ActionType, n: usize) -> Vec<(ActionType, f64)> {
        let i = from.index();
        let mut successors: Vec<(ActionType, f64)> = ActionType::ALL
            .iter()
            .filter_map(|&to| {
                let w = self.weights[i][to.index()];
                if w > 0.0 {
                    Some((to, w))
                } else {
                    None
                }
            })
            .collect();

        successors.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        successors.truncate(n);
        successors
    }

    /// Get all edges with weight above a threshold, as (from, to, weight) triples.
    pub fn active_edges(&self, threshold: f64) -> Vec<(ActionType, ActionType, f64)> {
        let mut edges = Vec::new();
        for i in 0..NODE_COUNT {
            for j in 0..NODE_COUNT {
                if self.weights[i][j] > threshold {
                    if let (Some(from), Some(to)) = (ActionType::from_index(i), ActionType::from_index(j)) {
                        edges.push((from, to, self.weights[i][j]));
                    }
                }
            }
        }
        edges
    }

    /// Total weight in the matrix (sum of all edges). Useful for diagnostics.
    pub fn total_weight(&self) -> f64 {
        self.weights.iter().flat_map(|row| row.iter()).sum()
    }

    /// Seed initial edge weights based on MITRE ATT&CK common kill-chain sequences.
    ///
    /// These are well-known attack progressions. Real-world observations
    /// will modify these weights via Hebbian learning. Initial seeding
    /// ensures the graph is useful from first deployment, not just
    /// after accumulating enough observations.
    ///
    /// DEFENSE CONTEXT: These weights represent "if we see A, how likely
    /// is B to follow in an attack?" -- detection probabilities, not instructions.
    fn seed_mitre_weights(&mut self) {
        use ActionType::*;

        // === PRIMARY KILL CHAIN: Recon -> Enum -> Exploit -> Exfil ===
        // The classic progression. Strong initial edges.
        self.set(Reconnaissance, Enumeration, 2.0);
        self.set(Enumeration, VulnerabilityScan, 1.8);
        self.set(VulnerabilityScan, Exploitation, 2.5);
        self.set(Exploitation, PrivilegeEscalation, 2.0);
        self.set(PrivilegeEscalation, LateralMovement, 1.8);
        self.set(LateralMovement, DataExfiltration, 1.5);

        // === CREDENTIAL-BASED CHAIN ===
        // Common in automated attacks: scan, find login, brute force, exploit
        self.set(Reconnaissance, CredentialAttack, 1.5);
        self.set(Enumeration, CredentialAttack, 1.8);
        self.set(CredentialAttack, Exploitation, 1.5);
        self.set(CredentialAttack, LateralMovement, 1.2);

        // === PERSISTENCE CHAINS ===
        // After initial access, attackers establish persistence
        self.set(Exploitation, Persistence, 1.8);
        self.set(PrivilegeEscalation, Persistence, 2.0);
        self.set(Persistence, CommandControl, 1.5);

        // === C2 ESTABLISHMENT ===
        // C2 often follows exploitation or persistence
        self.set(Exploitation, CommandControl, 1.2);
        self.set(CommandControl, DataExfiltration, 1.8);
        self.set(CommandControl, LateralMovement, 1.5);

        // === LATERAL MOVEMENT LOOPS ===
        // Attackers pivot and repeat
        self.set(LateralMovement, Reconnaissance, 0.8);
        self.set(LateralMovement, CredentialAttack, 1.0);
        self.set(LateralMovement, Exploitation, 1.0);

        // === RECON VARIATIONS ===
        // Recon can lead to vuln scan directly
        self.set(Reconnaissance, VulnerabilityScan, 1.5);

        // === EXFILTRATION CHAINS ===
        // After privilege escalation or lateral movement
        self.set(PrivilegeEscalation, DataExfiltration, 1.2);

        // === SELF-LOOPS (repeated action types) ===
        // Moderate self-reinforcement for sustained activity of same type
        // (e.g., ongoing port scanning, repeated brute force)
        self.set(Reconnaissance, Reconnaissance, 0.3);
        self.set(CredentialAttack, CredentialAttack, 0.5);
        self.set(Enumeration, Enumeration, 0.3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_matrix_is_zero() {
        let matrix = EdgeMatrix::new(HebbianParams::default());
        for i in 0..NODE_COUNT {
            for j in 0..NODE_COUNT {
                assert_eq!(matrix.weights[i][j], 0.0);
            }
        }
    }

    #[test]
    fn test_seeded_matrix_has_weights() {
        let matrix = EdgeMatrix::new_seeded(HebbianParams::default());
        // Primary kill chain edge should exist
        assert!(matrix.get(ActionType::Reconnaissance, ActionType::Enumeration) > 0.0);
        assert!(matrix.get(ActionType::VulnerabilityScan, ActionType::Exploitation) > 0.0);
    }

    #[test]
    fn test_hebbian_strengthening() {
        let mut matrix = EdgeMatrix::new(HebbianParams::default());
        let initial = matrix.get(ActionType::Reconnaissance, ActionType::Enumeration);
        assert_eq!(initial, 0.0);

        matrix.strengthen(ActionType::Reconnaissance, ActionType::Enumeration, 1.0, 1.0);
        let after = matrix.get(ActionType::Reconnaissance, ActionType::Enumeration);
        assert!(after > 0.0);
        assert_eq!(after, 0.05); // learning_rate * 1.0 * 1.0
    }

    #[test]
    fn test_weight_capping() {
        let params = HebbianParams {
            max_weight: 1.0,
            ..Default::default()
        };
        let mut matrix = EdgeMatrix::new(params);
        // Strengthen many times -- should cap at max_weight
        for _ in 0..100 {
            matrix.strengthen(ActionType::Reconnaissance, ActionType::Enumeration, 1.0, 1.0);
        }
        assert!(matrix.get(ActionType::Reconnaissance, ActionType::Enumeration) <= 1.0);
    }

    #[test]
    fn test_decay() {
        let mut matrix = EdgeMatrix::new_seeded(HebbianParams::default());
        let before = matrix.get(ActionType::Reconnaissance, ActionType::Enumeration);

        matrix.decay();
        let after = matrix.get(ActionType::Reconnaissance, ActionType::Enumeration);
        assert!(after < before);
        assert!(after > 0.0); // One decay shouldn't zero a seeded weight
    }

    #[test]
    fn test_chain_strength() {
        let matrix = EdgeMatrix::new_seeded(HebbianParams::default());
        let chain = vec![
            ActionType::Reconnaissance,
            ActionType::Enumeration,
            ActionType::VulnerabilityScan,
            ActionType::Exploitation,
        ];
        let strength = matrix.chain_strength(&chain);
        assert!(strength > 0.0);
    }

    #[test]
    fn test_chain_strength_broken() {
        let matrix = EdgeMatrix::new(HebbianParams::default());
        // Empty matrix: all chains are broken
        let chain = vec![ActionType::Reconnaissance, ActionType::Enumeration];
        assert_eq!(matrix.chain_strength(&chain), 0.0);
    }

    #[test]
    fn test_strongest_successors() {
        let matrix = EdgeMatrix::new_seeded(HebbianParams::default());
        let succs = matrix.strongest_successors(ActionType::Reconnaissance, 3);
        assert!(!succs.is_empty());
        // Should be sorted by weight descending
        for window in succs.windows(2) {
            assert!(window[0].1 >= window[1].1);
        }
    }

    #[test]
    fn test_decay_zeros_small_weights() {
        let mut matrix = EdgeMatrix::new(HebbianParams {
            min_weight: 0.01,
            decay_rate: 0.5,
            ..Default::default()
        });
        matrix.set(ActionType::Reconnaissance, ActionType::Enumeration, 0.015);
        matrix.decay(); // 0.015 * 0.5 = 0.0075 < 0.01 -> zeroed
        assert_eq!(matrix.get(ActionType::Reconnaissance, ActionType::Enumeration), 0.0);
    }
}

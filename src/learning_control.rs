//! # Learning Control Valve
//!
//! Runtime control over the Hebbian attack graph's learning behavior.
//!
//! Learning lives inside `DetectionEngine::process_events()` where it
//! architecturally belongs. This module provides external knobs so
//! operators can pause, resume, throttle, or adjust learning without
//! cracking open the pipeline.
//!
//! Exposed via the dashboard's JSON API endpoints:
//! - `GET  /api/learning/status`       - current state
//! - `POST /api/learning/pause`        - pause learning (detection continues)
//! - `POST /api/learning/resume`       - resume learning
//! - `POST /api/learning/set_rate`     - set rate multiplier (0.0-2.0)
//! - `POST /api/learning/set_batch_freq` - set batch frequency (min 1)

use serde::{Deserialize, Serialize};

/// Runtime control for the Hebbian learning subsystem.
///
/// This is a control valve, not the learning itself. The graph's
/// `learn()` / `learn_with_rate()` methods do the actual Hebbian
/// updates. This struct determines IF and HOW FAST those updates
/// happen on each event batch.
#[derive(Debug, Clone)]
pub struct LearningControl {
    /// Whether learning is currently enabled.
    /// When false, detection continues but the graph does not update.
    pub enabled: bool,

    /// Multiplier applied to the Hebbian learning rate.
    /// 0.0 = no learning (same effect as pausing).
    /// 1.0 = default rate.
    /// 2.0 = double speed learning.
    /// Clamped to [0.0, 2.0].
    pub rate_multiplier: f64,

    /// Learn every N event batches. Default 1 (every batch).
    /// Setting to 3 means learn on every 3rd batch, reducing
    /// CPU cost at the expense of learning granularity.
    pub batch_frequency: u32,

    /// Internal counter for batch frequency tracking.
    batch_counter: u32,
}

/// Snapshot of learning control state for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStatus {
    pub enabled: bool,
    pub rate_multiplier: f64,
    pub batch_frequency: u32,
    pub batch_counter: u32,
}

impl LearningControl {
    /// Create a new LearningControl with default settings.
    ///
    /// Defaults: enabled=true, rate=1.0, frequency=1, counter=0.
    pub fn new() -> Self {
        Self {
            enabled: true,
            rate_multiplier: 1.0,
            batch_frequency: 1,
            batch_counter: 0,
        }
    }

    /// Check whether learning should happen on this batch.
    ///
    /// Increments the internal counter and returns true when:
    /// 1. Learning is enabled, AND
    /// 2. The counter has reached the batch_frequency threshold.
    ///
    /// When it returns true, the counter resets to 0.
    pub fn should_learn(&mut self) -> bool {
        if !self.enabled {
            return false;
        }

        self.batch_counter += 1;

        if self.batch_counter >= self.batch_frequency {
            self.batch_counter = 0;
            true
        } else {
            false
        }
    }

    /// Get the effective learning rate multiplier, clamped to [0.0, 2.0].
    pub fn effective_rate(&self) -> f64 {
        self.rate_multiplier.clamp(0.0, 2.0)
    }

    /// Pause learning. Detection continues; graph stops updating.
    pub fn pause(&mut self) {
        self.enabled = false;
    }

    /// Resume learning from where it left off.
    pub fn resume(&mut self) {
        self.enabled = true;
    }

    /// Set the rate multiplier. Clamped to [0.0, 2.0].
    pub fn set_rate(&mut self, rate: f64) {
        self.rate_multiplier = rate.clamp(0.0, 2.0);
    }

    /// Set the batch frequency. Minimum 1.
    pub fn set_batch_frequency(&mut self, freq: u32) {
        self.batch_frequency = freq.max(1);
    }

    /// Get a snapshot of current state for reporting.
    pub fn status(&self) -> LearningStatus {
        LearningStatus {
            enabled: self.enabled,
            rate_multiplier: self.rate_multiplier,
            batch_frequency: self.batch_frequency,
            batch_counter: self.batch_counter,
        }
    }
}

impl Default for LearningControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_learning_control_defaults() {
        let ctrl = LearningControl::new();
        assert!(ctrl.enabled);
        assert_eq!(ctrl.rate_multiplier, 1.0);
        assert_eq!(ctrl.batch_frequency, 1);

        let status = ctrl.status();
        assert!(status.enabled);
        assert_eq!(status.rate_multiplier, 1.0);
        assert_eq!(status.batch_frequency, 1);
        assert_eq!(status.batch_counter, 0);
    }

    #[test]
    fn test_learning_pause_resume() {
        let mut ctrl = LearningControl::new();

        // Should learn when enabled
        assert!(ctrl.should_learn());

        // Pause - should not learn
        ctrl.pause();
        assert!(!ctrl.enabled);
        assert!(!ctrl.should_learn());
        assert!(!ctrl.should_learn());

        // Resume - should learn again
        ctrl.resume();
        assert!(ctrl.enabled);
        assert!(ctrl.should_learn());
    }

    #[test]
    fn test_batch_frequency() {
        let mut ctrl = LearningControl::new();
        ctrl.set_batch_frequency(3);

        // Batch 1: counter goes to 1, not yet
        assert!(!ctrl.should_learn());
        // Batch 2: counter goes to 2, not yet
        assert!(!ctrl.should_learn());
        // Batch 3: counter reaches 3, learn and reset
        assert!(ctrl.should_learn());

        // Next cycle: same pattern
        assert!(!ctrl.should_learn());
        assert!(!ctrl.should_learn());
        assert!(ctrl.should_learn());
    }

    #[test]
    fn test_rate_clamping() {
        let mut ctrl = LearningControl::new();

        // Above 2.0 clamps to 2.0
        ctrl.set_rate(5.0);
        assert_eq!(ctrl.effective_rate(), 2.0);
        assert_eq!(ctrl.rate_multiplier, 2.0);

        // Below 0.0 clamps to 0.0
        ctrl.set_rate(-1.0);
        assert_eq!(ctrl.effective_rate(), 0.0);
        assert_eq!(ctrl.rate_multiplier, 0.0);

        // Normal value passes through
        ctrl.set_rate(0.5);
        assert_eq!(ctrl.effective_rate(), 0.5);
        assert_eq!(ctrl.rate_multiplier, 0.5);

        // Edge values
        ctrl.set_rate(0.0);
        assert_eq!(ctrl.effective_rate(), 0.0);

        ctrl.set_rate(2.0);
        assert_eq!(ctrl.effective_rate(), 2.0);
    }

    #[test]
    fn test_batch_frequency_minimum() {
        let mut ctrl = LearningControl::new();

        // Setting to 0 should clamp to 1
        ctrl.set_batch_frequency(0);
        assert_eq!(ctrl.batch_frequency, 1);

        // Setting to 1 should work
        ctrl.set_batch_frequency(1);
        assert_eq!(ctrl.batch_frequency, 1);
        // With freq=1, every call should learn
        assert!(ctrl.should_learn());
        assert!(ctrl.should_learn());
    }

    #[test]
    fn test_status_snapshot() {
        let mut ctrl = LearningControl::new();
        ctrl.set_rate(1.5);
        ctrl.set_batch_frequency(4);
        ctrl.should_learn(); // counter = 1
        ctrl.should_learn(); // counter = 2

        let status = ctrl.status();
        assert!(status.enabled);
        assert_eq!(status.rate_multiplier, 1.5);
        assert_eq!(status.batch_frequency, 4);
        assert_eq!(status.batch_counter, 2);
    }

    #[test]
    fn test_paused_does_not_increment_counter() {
        let mut ctrl = LearningControl::new();
        ctrl.set_batch_frequency(3);
        ctrl.pause();

        // Calling should_learn while paused should not increment counter
        ctrl.should_learn();
        ctrl.should_learn();
        ctrl.should_learn();

        let status = ctrl.status();
        assert_eq!(status.batch_counter, 0);
    }
}

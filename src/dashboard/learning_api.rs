//! # Learning Control API Handlers
//!
//! Request/response types and handler functions for the learning control
//! valve. These are transport-agnostic -- they work whether called from
//! the HTTP dashboard, an MCP tool server, or the CLI.
//!
//! ## Endpoints (when wired to HTTP):
//! - `GET  /api/learning/status`         -> LearningStatusResponse
//! - `POST /api/learning/pause`          -> LearningStatusResponse
//! - `POST /api/learning/resume`         -> LearningStatusResponse
//! - `POST /api/learning/set_rate`       -> LearningStatusResponse (body: {"value": f64})
//! - `POST /api/learning/set_batch_freq` -> LearningStatusResponse (body: {"value": u32})

use serde::{Deserialize, Serialize};

use crate::learning_control::{LearningControl, LearningStatus};

/// Response envelope for all learning control operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStatusResponse {
    /// Whether the operation succeeded.
    pub ok: bool,

    /// Human-readable message about what happened.
    pub message: String,

    /// Current learning control state after the operation.
    pub status: LearningStatus,
}

/// Request body for set_rate and set_batch_freq.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningValueRequest {
    pub value: f64,
}

/// Get the current learning control status.
pub fn handle_learning_status(ctrl: &LearningControl) -> LearningStatusResponse {
    LearningStatusResponse {
        ok: true,
        message: format!(
            "Learning is {}",
            if ctrl.status().enabled { "active" } else { "paused" }
        ),
        status: ctrl.status(),
    }
}

/// Pause learning. Detection continues; graph stops updating.
pub fn handle_learning_pause(ctrl: &mut LearningControl) -> LearningStatusResponse {
    ctrl.pause();
    LearningStatusResponse {
        ok: true,
        message: "Learning paused. Detection continues; graph will not update.".to_string(),
        status: ctrl.status(),
    }
}

/// Resume learning from where it left off.
pub fn handle_learning_resume(ctrl: &mut LearningControl) -> LearningStatusResponse {
    ctrl.resume();
    LearningStatusResponse {
        ok: true,
        message: "Learning resumed.".to_string(),
        status: ctrl.status(),
    }
}

/// Set the learning rate multiplier. Value is clamped to [0.0, 2.0].
pub fn handle_learning_set_rate(
    ctrl: &mut LearningControl,
    value: f64,
) -> LearningStatusResponse {
    ctrl.set_rate(value);
    LearningStatusResponse {
        ok: true,
        message: format!(
            "Learning rate multiplier set to {:.2} (effective: {:.2})",
            ctrl.status().rate_multiplier,
            ctrl.effective_rate(),
        ),
        status: ctrl.status(),
    }
}

/// Set the batch frequency. Value is clamped to minimum 1.
pub fn handle_learning_set_batch_freq(
    ctrl: &mut LearningControl,
    value: u32,
) -> LearningStatusResponse {
    ctrl.set_batch_frequency(value);
    LearningStatusResponse {
        ok: true,
        message: format!(
            "Batch frequency set to {} (learn every {} event batches)",
            ctrl.status().batch_frequency,
            ctrl.status().batch_frequency,
        ),
        status: ctrl.status(),
    }
}

/// Route a learning control command by name.
///
/// This is the single entry point for CLI, MCP, or HTTP dispatch.
/// Commands: "status", "pause", "resume", "set_rate", "set_batch_freq".
pub fn route_learning_command(
    ctrl: &mut LearningControl,
    command: &str,
    value: Option<f64>,
) -> LearningStatusResponse {
    match command {
        "status" => handle_learning_status(ctrl),
        "pause" => handle_learning_pause(ctrl),
        "resume" => handle_learning_resume(ctrl),
        "set_rate" => {
            let v = value.unwrap_or(1.0);
            handle_learning_set_rate(ctrl, v)
        }
        "set_batch_freq" => {
            let v = value.unwrap_or(1.0) as u32;
            handle_learning_set_batch_freq(ctrl, v)
        }
        unknown => LearningStatusResponse {
            ok: false,
            message: format!(
                "Unknown learning command: '{}'. Valid: status, pause, resume, set_rate, set_batch_freq",
                unknown
            ),
            status: ctrl.status(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_status() {
        let mut ctrl = LearningControl::new();
        let resp = route_learning_command(&mut ctrl, "status", None);
        assert!(resp.ok);
        assert!(resp.status.enabled);
    }

    #[test]
    fn test_route_pause_resume() {
        let mut ctrl = LearningControl::new();

        let resp = route_learning_command(&mut ctrl, "pause", None);
        assert!(resp.ok);
        assert!(!resp.status.enabled);

        let resp = route_learning_command(&mut ctrl, "resume", None);
        assert!(resp.ok);
        assert!(resp.status.enabled);
    }

    #[test]
    fn test_route_set_rate() {
        let mut ctrl = LearningControl::new();
        let resp = route_learning_command(&mut ctrl, "set_rate", Some(0.75));
        assert!(resp.ok);
        assert_eq!(resp.status.rate_multiplier, 0.75);
    }

    #[test]
    fn test_route_set_batch_freq() {
        let mut ctrl = LearningControl::new();
        let resp = route_learning_command(&mut ctrl, "set_batch_freq", Some(5.0));
        assert!(resp.ok);
        assert_eq!(resp.status.batch_frequency, 5);
    }

    #[test]
    fn test_route_unknown_command() {
        let mut ctrl = LearningControl::new();
        let resp = route_learning_command(&mut ctrl, "explode", None);
        assert!(!resp.ok);
        assert!(resp.message.contains("Unknown"));
    }

    #[test]
    fn test_json_roundtrip() {
        let mut ctrl = LearningControl::new();
        ctrl.set_rate(1.5);
        let resp = handle_learning_status(&ctrl);
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: LearningStatusResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status.rate_multiplier, 1.5);
        assert!(parsed.ok);
    }
}

//! # Combined Threat Scorer
//!
//! The heart of SENTINEL Shield's detection system. Combines velocity,
//! coverage, and correlation sub-scores into a single threat score using
//! configurable weights.
//!
//! ## Scoring Model
//!
//! The combined score is a weighted sum:
//!
//! ```text
//! score = (velocity * Wv) + (coverage * Wc) + (correlation * Wr)
//! ```
//!
//! Where Wv + Wc + Wr = 1.0 (normalized weights).
//!
//! Default weights (tuned for AI attack detection):
//! - Velocity:    0.40 - Speed is the primary AI signature
//! - Coverage:    0.35 - Breadth of probing is secondary
//! - Correlation: 0.25 - Tight recon-to-exploit timing is confirming
//!
//! ## Adaptive Scoring
//!
//! The scorer also provides an adaptive mode that adjusts weights based on
//! the attack graph's learned patterns. If the graph has seen many attacks
//! that start with broad scanning, coverage weight increases. If the graph
//! has seen rapid-pivot attacks, correlation weight increases.

use crate::{ScoreWeights, ThreatScore};

/// Score a single attack session using the standard weighted model.
///
/// This is the primary scoring function. It takes pre-computed sub-scores
/// and combines them with weights.
///
/// # Arguments
/// * `velocity` - Velocity sub-score [0.0, 1.0]
/// * `coverage` - Coverage sub-score [0.0, 1.0]
/// * `correlation` - Correlation sub-score [0.0, 1.0]
/// * `weights` - The scoring weights to apply
///
/// # Returns
/// A `ThreatScore` with the combined score and individual components.
pub fn score_session(
    velocity: f64,
    coverage: f64,
    correlation: f64,
    weights: &ScoreWeights,
) -> ThreatScore {
    ThreatScore::new(velocity, coverage, correlation, weights)
}

/// Score with a confidence multiplier based on event count.
///
/// Low event counts should reduce confidence in the score. A single
/// failed login is not the same threat as 50 failed logins even if
/// the per-event rate looks similar.
///
/// # Arguments
/// * `velocity` - Velocity sub-score [0.0, 1.0]
/// * `coverage` - Coverage sub-score [0.0, 1.0]
/// * `correlation` - Correlation sub-score [0.0, 1.0]
/// * `weights` - The scoring weights to apply
/// * `event_count` - Total events in the session
/// * `min_events_for_full_confidence` - Events needed for confidence = 1.0
///
/// # Returns
/// A `ThreatScore` scaled by confidence factor.
pub fn score_with_confidence(
    velocity: f64,
    coverage: f64,
    correlation: f64,
    weights: &ScoreWeights,
    event_count: usize,
    min_events_for_full_confidence: usize,
) -> ThreatScore {
    let confidence = if min_events_for_full_confidence == 0 {
        1.0
    } else {
        (event_count as f64 / min_events_for_full_confidence as f64).min(1.0)
    };

    // Apply confidence as a scaling factor to each sub-score before combining.
    // This ensures low-event sessions don't trigger false positives.
    let scaled_v = velocity * confidence;
    let scaled_c = coverage * confidence;
    let scaled_r = correlation * confidence;

    ThreatScore::new(scaled_v, scaled_c, scaled_r, weights)
}

/// Compute adaptive weights based on observed attack patterns.
///
/// The Hebbian graph encodes which attack phases frequently co-occur.
/// We use this to adjust weights:
///
/// - If the graph shows strong recon->exploit edges (fast pivots are common),
///   increase the correlation weight.
/// - If the graph shows strong broad-scan patterns (many ports in sequence),
///   increase the coverage weight.
/// - Base velocity weight adjusts to maintain sum = 1.0.
///
/// # Arguments
/// * `base_weights` - The configured base weights.
/// * `recon_exploit_strength` - Hebbian edge weight between recon and exploit phases.
/// * `broad_scan_strength` - Hebbian edge weight for broad scanning patterns.
/// * `adaptation_rate` - How much to adjust (0.0 = no change, 1.0 = full shift).
///
/// # Returns
/// Adapted `ScoreWeights` that sum to 1.0.
pub fn compute_adaptive_weights(
    base_weights: &ScoreWeights,
    recon_exploit_strength: f64,
    broad_scan_strength: f64,
    adaptation_rate: f64,
) -> ScoreWeights {
    let rate = adaptation_rate.clamp(0.0, 1.0);

    // Normalize Hebbian strengths to [0, 1] range
    let max_strength = recon_exploit_strength.max(broad_scan_strength).max(1.0);
    let norm_recon = recon_exploit_strength / max_strength;
    let norm_broad = broad_scan_strength / max_strength;

    // Compute adjustments - shift weight toward whichever signal
    // the graph has learned is most predictive
    let corr_adjustment = norm_recon * rate * 0.15; // max 15% shift
    let cov_adjustment = norm_broad * rate * 0.15;

    let new_correlation = (base_weights.correlation + corr_adjustment).min(0.5);
    let new_coverage = (base_weights.coverage + cov_adjustment).min(0.5);

    // Velocity absorbs the remainder to maintain sum = 1.0
    let new_velocity = (1.0 - new_correlation - new_coverage).max(0.1);

    // Normalize to ensure exact sum = 1.0
    let sum = new_velocity + new_coverage + new_correlation;
    ScoreWeights {
        velocity: new_velocity / sum,
        coverage: new_coverage / sum,
        correlation: new_correlation / sum,
    }
}

/// Determine the threat level label for display purposes.
///
/// # Arguments
/// * `score` - A ThreatScore to classify.
///
/// # Returns
/// A human-readable threat level string.
pub fn threat_level_label(score: &ThreatScore) -> &'static str {
    match score.combined {
        s if s >= 0.9 => "CRITICAL",
        s if s >= 0.7 => "HIGH",
        s if s >= 0.5 => "MEDIUM",
        s if s >= 0.3 => "LOW",
        _ => "MINIMAL",
    }
}

/// Format a ThreatScore as a compact string for logging.
///
/// Example: "THREAT 0.82 [V:0.95 C:0.72 R:0.68] HIGH"
pub fn format_score(score: &ThreatScore) -> String {
    format!(
        "THREAT {:.2} [V:{:.2} C:{:.2} R:{:.2}] {}",
        score.combined,
        score.velocity,
        score.coverage,
        score.correlation,
        threat_level_label(score),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_weights() -> ScoreWeights {
        ScoreWeights {
            velocity: 0.4,
            coverage: 0.35,
            correlation: 0.25,
        }
    }

    #[test]
    fn test_zero_scores_produce_zero_threat() {
        let score = score_session(0.0, 0.0, 0.0, &default_weights());
        assert_eq!(score.combined, 0.0);
    }

    #[test]
    fn test_max_scores_produce_one() {
        let score = score_session(1.0, 1.0, 1.0, &default_weights());
        assert!((score.combined - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_weighted_combination() {
        let weights = default_weights();
        let score = score_session(1.0, 0.0, 0.0, &weights);
        assert!((score.combined - 0.4).abs() < f64::EPSILON);

        let score = score_session(0.0, 1.0, 0.0, &weights);
        assert!((score.combined - 0.35).abs() < f64::EPSILON);

        let score = score_session(0.0, 0.0, 1.0, &weights);
        assert!((score.combined - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_confidence_scaling() {
        let weights = default_weights();

        // Full confidence (10+ events, min=10)
        let full = score_with_confidence(0.8, 0.6, 0.5, &weights, 10, 10);

        // Half confidence (5 events, min=10)
        let half = score_with_confidence(0.8, 0.6, 0.5, &weights, 5, 10);

        assert!(half.combined < full.combined);
        assert!((half.combined - full.combined * 0.5).abs() < 0.01);
    }

    #[test]
    fn test_adaptive_weights_sum_to_one() {
        let base = default_weights();
        let adapted = compute_adaptive_weights(&base, 5.0, 3.0, 0.8);
        let sum = adapted.velocity + adapted.coverage + adapted.correlation;
        assert!((sum - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_threat_level_labels() {
        let weights = default_weights();

        let critical = score_session(1.0, 1.0, 1.0, &weights);
        assert_eq!(threat_level_label(&critical), "CRITICAL");

        let minimal = score_session(0.0, 0.0, 0.0, &weights);
        assert_eq!(threat_level_label(&minimal), "MINIMAL");
    }

    #[test]
    fn test_format_score_output() {
        let weights = default_weights();
        let score = score_session(0.95, 0.72, 0.68, &weights);
        let formatted = format_score(&score);
        assert!(formatted.contains("THREAT"));
        assert!(formatted.contains("V:0.95"));
        assert!(formatted.contains("C:0.72"));
        assert!(formatted.contains("R:0.68"));
    }
}

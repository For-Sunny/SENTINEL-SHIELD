//! # Correlation Detector
//!
//! Measures the temporal correlation between discovery and exploitation
//! from the same source IP. The signature of AI-orchestrated attacks is
//! the speed at which reconnaissance findings are acted upon.
//!
//! A human attacker might scan a target, go away for hours or days, then
//! come back with exploits. An AI attacker discovers a service and attempts
//! exploitation within seconds or minutes - machine speed.
//!
//! Correlation score is based on how quickly reconnaissance events are
//! followed by exploit attempts from the same source.

use crate::{AttackPhase, DetectionEvent, EventType};

/// Calculate the correlation score for events from a single source.
///
/// Looks for pairs of (reconnaissance, exploit_attempt) events and measures
/// the time gap between them. Shorter gaps = higher score = more likely AI.
///
/// # Arguments
/// * `events` - Events from a single source IP, ordered by timestamp.
/// * `min_gap_secs` - Minimum gap to count (below this is instant, scores 1.0).
/// * `max_gap_secs` - Maximum gap to count (above this is uncorrelated, scores 0.0).
///
/// # Returns
/// A score in [0.0, 1.0] representing how tightly correlated discovery
/// and exploitation are from this source.
pub fn calculate_correlation_score(
    events: &[DetectionEvent],
    min_gap_secs: u64,
    max_gap_secs: u64,
) -> f64 {
    if events.len() < 2 || max_gap_secs <= min_gap_secs {
        return 0.0;
    }

    // Separate events into discovery (recon) and exploitation categories
    let recon_events: Vec<&DetectionEvent> = events
        .iter()
        .filter(|e| is_discovery_event(&e.event_type))
        .collect();

    let exploit_events: Vec<&DetectionEvent> = events
        .iter()
        .filter(|e| is_exploitation_event(&e.event_type))
        .collect();

    if recon_events.is_empty() || exploit_events.is_empty() {
        return 0.0;
    }

    // Find the tightest correlation: for each exploit event, find the
    // closest preceding recon event and measure the gap.
    let mut correlation_scores: Vec<f64> = Vec::new();

    for exploit in &exploit_events {
        // Find the most recent recon event before this exploit
        let closest_recon = recon_events
            .iter()
            .filter(|r| r.timestamp < exploit.timestamp)
            .max_by_key(|r| r.timestamp);

        if let Some(recon) = closest_recon {
            let gap_secs = (exploit.timestamp - recon.timestamp).num_seconds() as u64;

            if gap_secs <= min_gap_secs {
                // Below minimum gap: instant pivot, maximum suspicion
                correlation_scores.push(1.0);
            } else if gap_secs >= max_gap_secs {
                // Above maximum gap: uncorrelated
                correlation_scores.push(0.0);
            } else {
                // Linear decay between min and max gap
                // Shorter gap = higher score
                let range = (max_gap_secs - min_gap_secs) as f64;
                let offset = (gap_secs - min_gap_secs) as f64;
                correlation_scores.push(1.0 - (offset / range));
            }
        }
    }

    if correlation_scores.is_empty() {
        return 0.0;
    }

    // Return the maximum correlation found (worst case = most suspicious pair)
    correlation_scores
        .iter()
        .cloned()
        .fold(0.0_f64, f64::max)
}

/// Returns true if this event type represents a discovery/reconnaissance activity.
fn is_discovery_event(event_type: &EventType) -> bool {
    matches!(
        event_type,
        EventType::Reconnaissance | EventType::WebProbe | EventType::Suspicious
    )
}

/// Returns true if this event type represents an exploitation attempt.
fn is_exploitation_event(event_type: &EventType) -> bool {
    matches!(
        event_type,
        EventType::ExploitAttempt
            | EventType::BruteForce
            | EventType::CredentialStuffing
            | EventType::AuthFailure
    )
}

/// Compute phase-transition correlation using the attack graph phases.
///
/// Instead of just recon->exploit pairs, this checks for any sequential
/// phase transitions that match known AI attack patterns.
///
/// # Arguments
/// * `events` - Events from a single source.
/// * `min_gap_secs` - Minimum gap for correlation.
/// * `max_gap_secs` - Maximum gap for correlation.
///
/// # Returns
/// Score in [0.0, 1.0] based on how many known phase transitions occur
/// within the correlation window.
pub fn calculate_phase_correlation(
    events: &[DetectionEvent],
    min_gap_secs: u64,
    max_gap_secs: u64,
) -> f64 {
    // TODO: Implementation steps:
    // 1. Convert each event to its AttackPhase
    // 2. Look for sequential phase transitions (e.g., Reconnaissance -> CredentialAccess)
    // 3. For each transition, measure the time gap
    // 4. Score each transition using the same linear decay as above
    // 5. Weight transitions by how indicative they are of AI orchestration:
    //    - Recon -> Exploit (high weight: 1.0)
    //    - Discovery -> CredentialAccess (medium weight: 0.8)
    //    - CredentialAccess -> LateralMovement (high weight: 1.0)
    //    - Any -> Exfiltration (critical weight: 1.0)
    // 6. Return weighted average of transition scores

    if events.len() < 2 {
        return 0.0;
    }

    let mut transition_scores: Vec<f64> = Vec::new();

    for window in events.windows(2) {
        let phase_a = AttackPhase::from(&window[0].event_type);
        let phase_b = AttackPhase::from(&window[1].event_type);

        // Only score if phases are different (transition, not repetition)
        if phase_a != phase_b {
            let gap = (window[1].timestamp - window[0].timestamp).num_seconds() as u64;
            if gap <= max_gap_secs {
                let score = if gap <= min_gap_secs {
                    1.0
                } else {
                    let range = (max_gap_secs - min_gap_secs) as f64;
                    let offset = (gap - min_gap_secs) as f64;
                    1.0 - (offset / range)
                };
                transition_scores.push(score);
            }
        }
    }

    if transition_scores.is_empty() {
        return 0.0;
    }

    transition_scores.iter().cloned().fold(0.0_f64, f64::max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectionEvent, EventType, LogSourceType};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_event(secs_ago: i64, event_type: EventType) -> DetectionEvent {
        DetectionEvent {
            timestamp: Utc::now() - chrono::Duration::seconds(secs_ago),
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            target_port: Some(80),
            target_endpoint: Some("/api".to_string()),
            event_type,
            source: LogSourceType::WebAccessLog,
            raw_line: String::new(),
        }
    }

    #[test]
    fn test_no_events_returns_zero() {
        assert_eq!(calculate_correlation_score(&[], 1, 300), 0.0);
    }

    #[test]
    fn test_only_recon_returns_zero() {
        let events = vec![
            make_event(30, EventType::Reconnaissance),
            make_event(20, EventType::WebProbe),
        ];
        assert_eq!(calculate_correlation_score(&events, 1, 300), 0.0);
    }

    #[test]
    fn test_fast_pivot_high_score() {
        // Recon at 10s ago, exploit at 8s ago = 2 second gap
        let events = vec![
            make_event(10, EventType::Reconnaissance),
            make_event(8, EventType::ExploitAttempt),
        ];
        let score = calculate_correlation_score(&events, 1, 300);
        assert!(score > 0.9, "Fast pivot should score high, got {}", score);
    }

    #[test]
    fn test_slow_pivot_low_score() {
        // Recon at 300s ago, exploit at 5s ago = 295 second gap
        let events = vec![
            make_event(300, EventType::Reconnaissance),
            make_event(5, EventType::ExploitAttempt),
        ];
        let score = calculate_correlation_score(&events, 1, 300);
        assert!(score < 0.1, "Slow pivot should score low, got {}", score);
    }
}

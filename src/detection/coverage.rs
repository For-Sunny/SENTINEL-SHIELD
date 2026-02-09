//! # Coverage Detector
//!
//! Measures the breadth of probing from a single source IP. AI-orchestrated
//! attacks systematically enumerate targets - scanning many ports, probing
//! many endpoints, testing many services. A human attacker might focus on
//! one or two known vulnerabilities; an AI scans everything.
//!
//! Coverage score is computed as:
//!   score = min(1.0, unique_targets / saturation_threshold)
//!
//! Where unique_targets = unique_ports + unique_endpoints hit by the source.

use crate::AttackSession;

/// Calculate the coverage score for an attack session.
///
/// Measures how broadly the source is scanning by counting unique
/// ports and endpoints targeted.
///
/// # Arguments
/// * `session` - The attack session to evaluate.
/// * `saturation` - Number of unique targets at which score saturates to 1.0.
///
/// # Returns
/// A score in [0.0, 1.0] representing breadth of probing activity.
pub fn calculate_coverage_score(
    session: &AttackSession,
    saturation: u64,
) -> f64 {
    if saturation == 0 {
        return 0.0;
    }

    let unique_targets = session.targeted_ports.len() + session.targeted_endpoints.len();
    (unique_targets as f64 / saturation as f64).min(1.0)
}

/// Calculate coverage with category weighting.
///
/// Different types of targets carry different weight:
/// - Unique ports suggest port scanning (weight: 1.0)
/// - Unique endpoints suggest web enumeration (weight: 1.5, more deliberate)
/// - Unique services (derived from port) suggest service discovery (weight: 1.2)
///
/// # Arguments
/// * `session` - The attack session to evaluate.
/// * `saturation` - Effective weighted target count at which score saturates.
///
/// # Returns
/// Weighted coverage score in [0.0, 1.0].
pub fn calculate_weighted_coverage_score(
    session: &AttackSession,
    saturation: f64,
) -> f64 {
    // TODO: Implementation steps:
    // 1. Count unique ports (weight 1.0 each)
    // 2. Count unique endpoints (weight 1.5 each - web probing is more targeted)
    // 3. Identify well-known service ports (22=SSH, 80/443=HTTP, 3306=MySQL, etc.)
    //    and add a service discovery bonus (weight 1.2 per unique service category)
    // 4. Sum weighted targets / saturation, clamp to [0.0, 1.0]
    //
    // The weighting reflects that an AI attacker probing multiple web endpoints
    // is more concerning than simply scanning sequential port numbers, because
    // endpoint probing requires knowledge of typical application structures.

    if saturation <= 0.0 {
        return 0.0;
    }

    let port_weight = 1.0;
    let endpoint_weight = 1.5;

    let weighted = (session.targeted_ports.len() as f64 * port_weight)
        + (session.targeted_endpoints.len() as f64 * endpoint_weight);

    (weighted / saturation).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackSession, DetectionEvent, EventType, LogSourceType};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_session_with_targets(ports: Vec<u16>, endpoints: Vec<&str>) -> AttackSession {
        let event = DetectionEvent {
            timestamp: Utc::now(),
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            target_port: None,
            target_endpoint: None,
            event_type: EventType::Reconnaissance,
            source: LogSourceType::Syslog,
            raw_line: String::new(),
        };
        let mut session = AttackSession::new(event);
        session.targeted_ports = ports;
        session.targeted_endpoints = endpoints.into_iter().map(String::from).collect();
        session
    }

    #[test]
    fn test_no_targets_zero_score() {
        let session = make_session_with_targets(vec![], vec![]);
        assert_eq!(calculate_coverage_score(&session, 20), 0.0);
    }

    #[test]
    fn test_few_targets_low_score() {
        let session = make_session_with_targets(vec![22, 80], vec!["/admin"]);
        let score = calculate_coverage_score(&session, 20);
        assert!(score > 0.0);
        assert!(score < 0.5);
    }

    #[test]
    fn test_many_targets_high_score() {
        let ports: Vec<u16> = (1..=15).collect();
        let endpoints = vec!["/admin", "/login", "/api", "/wp-admin", "/.env"];
        let session = make_session_with_targets(ports, endpoints);
        let score = calculate_coverage_score(&session, 20);
        assert_eq!(score, 1.0);
    }
}

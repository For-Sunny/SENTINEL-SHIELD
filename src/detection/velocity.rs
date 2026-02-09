//! # Velocity Detector
//!
//! Measures the rate of requests from a single source IP within a sliding
//! time window. AI-orchestrated attacks are characterized by inhuman speed -
//! hundreds or thousands of requests per minute from a single source.
//!
//! The velocity score is computed as:
//!   score = min(1.0, events_in_window / saturation_threshold)
//!
//! A sliding window approach counts events within the most recent N seconds.
//! Events older than the window are excluded from the count.

use chrono::Utc;
use crate::DetectionEvent;

/// Calculate the velocity score for a set of events from a single source.
///
/// # Arguments
/// * `events` - All events from a single source IP, ordered by timestamp.
/// * `window_secs` - The sliding window duration in seconds.
/// * `saturation` - Number of events at which the score saturates to 1.0.
///
/// # Returns
/// A score in [0.0, 1.0] representing how fast this source is generating events.
pub fn calculate_velocity_score(
    events: &[DetectionEvent],
    window_secs: u64,
    saturation: u64,
) -> f64 {
    if events.is_empty() || saturation == 0 {
        return 0.0;
    }

    let now = Utc::now();
    let window_start = now - chrono::Duration::seconds(window_secs as i64);

    // Count events within the sliding window
    let count_in_window = events
        .iter()
        .filter(|e| e.timestamp >= window_start)
        .count() as f64;

    // Normalize to [0.0, 1.0] using saturation threshold
    (count_in_window / saturation as f64).min(1.0)
}

/// Calculate velocity using a bucketed sliding window for higher precision.
///
/// Divides the window into sub-buckets to detect burst patterns within
/// the overall window. Returns the peak bucket rate normalized against
/// the expected rate.
///
/// # Arguments
/// * `events` - All events from a single source IP.
/// * `window_secs` - Total window duration.
/// * `bucket_count` - Number of sub-buckets to divide the window into.
/// * `saturation` - Events per bucket at which score saturates.
///
/// # Returns
/// Score in [0.0, 1.0] based on peak bucket density.
pub fn calculate_burst_velocity(
    events: &[DetectionEvent],
    window_secs: u64,
    bucket_count: usize,
    saturation: u64,
) -> f64 {
    // TODO: Implementation steps:
    // 1. Divide the window into `bucket_count` equal sub-windows
    // 2. Assign each event to its bucket based on timestamp
    // 3. Find the bucket with the highest event count
    // 4. Normalize: peak_count / (saturation / bucket_count)
    // 5. Clamp to [0.0, 1.0]
    //
    // This catches burst patterns that a simple average would miss.
    // An AI attacker might send 50 requests in 2 seconds then pause,
    // which averages to low velocity over 60s but is clearly automated.

    if events.is_empty() || saturation == 0 || bucket_count == 0 {
        return 0.0;
    }

    let now = Utc::now();
    let window_start = now - chrono::Duration::seconds(window_secs as i64);
    let bucket_duration_secs = window_secs as f64 / bucket_count as f64;

    let mut buckets = vec![0u64; bucket_count];

    for event in events.iter().filter(|e| e.timestamp >= window_start) {
        let offset = (now - event.timestamp).num_milliseconds() as f64 / 1000.0;
        let bucket_idx = (offset / bucket_duration_secs) as usize;
        if bucket_idx < bucket_count {
            buckets[bucket_idx] += 1;
        }
    }

    let peak = *buckets.iter().max().unwrap_or(&0) as f64;
    let per_bucket_saturation = saturation as f64 / bucket_count as f64;

    (peak / per_bucket_saturation).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectionEvent, EventType, LogSourceType};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_event(secs_ago: i64) -> DetectionEvent {
        DetectionEvent {
            timestamp: Utc::now() - chrono::Duration::seconds(secs_ago),
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            target_port: Some(22),
            target_endpoint: None,
            event_type: EventType::AuthFailure,
            source: LogSourceType::AuthLog,
            raw_line: String::new(),
        }
    }

    #[test]
    fn test_empty_events_returns_zero() {
        assert_eq!(calculate_velocity_score(&[], 60, 100), 0.0);
    }

    #[test]
    fn test_single_event_low_score() {
        let events = vec![make_event(5)];
        let score = calculate_velocity_score(&events, 60, 100);
        assert!(score > 0.0);
        assert!(score < 0.1);
    }

    #[test]
    fn test_saturation_caps_at_one() {
        let events: Vec<_> = (0..200).map(|i| make_event(i % 60)).collect();
        let score = calculate_velocity_score(&events, 60, 100);
        assert_eq!(score, 1.0);
    }
}

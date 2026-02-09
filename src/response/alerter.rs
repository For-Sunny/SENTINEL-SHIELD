//! # Alert System
//!
//! Sends alerts through multiple channels when threats are detected.
//! Supports:
//! - JSONL file alerts (always active, one JSON object per line)
//! - Webhook notifications (optional, via ureq HTTP POST)
//! - Email queue (optional, writes .eml files for external pickup)
//!
//! All alerts include:
//! - Timestamp (RFC 3339)
//! - Source IP
//! - Threat score breakdown (velocity, coverage, correlation)
//! - Threat level label (CRITICAL, HIGH, MEDIUM, LOW, MINIMAL)
//! - Human-readable reason

use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use crate::{ShieldResult, ThreatScore};
use crate::detection::scorer;

/// Write an alert entry as a JSON line to the alerts JSONL file.
///
/// Creates the file and parent directories if they don't exist.
/// Each alert is a single JSON object on its own line, making the file
/// easy to parse with standard tools (jq, grep, etc.).
///
/// # Arguments
/// * `log_path` - Path to the alert JSONL file (e.g., `alerts.jsonl`).
/// * `source_ip` - The threatening IP address.
/// * `score` - The threat score.
/// * `reason` - Human-readable description.
pub fn log_alert(
    log_path: &Path,
    source_ip: &IpAddr,
    score: &ThreatScore,
    reason: &str,
) -> ShieldResult<()> {
    let level = scorer::threat_level_label(score);
    let timestamp = chrono::Utc::now().to_rfc3339();

    let alert_obj = serde_json::json!({
        "timestamp": timestamp,
        "source_ip": source_ip.to_string(),
        "threat_score": score.combined,
        "velocity": score.velocity,
        "coverage": score.coverage,
        "correlation": score.correlation,
        "threat_level": level,
        "reason": reason,
    });

    let json_line = serde_json::to_string(&alert_obj)?;

    // Ensure parent directory exists
    if let Some(parent) = log_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    writeln!(file, "{}", json_line)?;
    file.flush()?;

    log::warn!(
        "[ALERT] {} | {} | {} | {} | {}",
        timestamp,
        level,
        source_ip,
        scorer::format_score(score),
        reason,
    );

    Ok(())
}

/// Send an alert via webhook (HTTP POST).
///
/// Sends a JSON payload via ureq to the configured webhook URL.
/// Compatible with Slack, Discord, PagerDuty, Microsoft Teams, and
/// generic HTTP endpoints.
///
/// Timeout: 5 seconds. Failures are logged but do not propagate as
/// errors to prevent webhook issues from disrupting the daemon.
///
/// # Arguments
/// * `webhook_url` - The URL to POST to (must start with http:// or https://).
/// * `source_ip` - The threatening IP address.
/// * `score` - The threat score.
/// * `reason` - Human-readable description.
pub fn send_webhook(
    webhook_url: &str,
    source_ip: &IpAddr,
    score: &ThreatScore,
    reason: &str,
) -> ShieldResult<()> {
    // Validate URL scheme
    if !webhook_url.starts_with("https://") && !webhook_url.starts_with("http://") {
        return Err(crate::ShieldError::Response(format!(
            "Webhook URL must start with http:// or https://, got: {}", webhook_url
        )));
    }

    let level = scorer::threat_level_label(score);
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Get hostname for context
    let hostname = hostname_string();

    let payload = serde_json::json!({
        "text": format!(
            "SENTINEL Shield Alert: [{}] Threat from {} - {}",
            level, source_ip, reason
        ),
        "timestamp": timestamp,
        "source_ip": source_ip.to_string(),
        "threat_score": score.combined,
        "velocity": score.velocity,
        "coverage": score.coverage,
        "correlation": score.correlation,
        "threat_level": level,
        "reason": reason,
        "hostname": hostname,
    });

    let payload_str = serde_json::to_string(&payload)?;

    // Use ureq for the HTTP POST with 5-second timeout
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let result = agent
        .post(webhook_url)
        .set("Content-Type", "application/json")
        .send_string(&payload_str);

    match result {
        Ok(response) => {
            log::info!(
                "[WEBHOOK] POST to {} succeeded (status {}): {} - {}",
                webhook_url,
                response.status(),
                source_ip,
                reason,
            );
        }
        Err(e) => {
            // Don't crash on webhook failure - log and continue
            log::warn!(
                "[WEBHOOK] POST to {} failed: {} (alert for {} still logged locally)",
                webhook_url,
                e,
                source_ip,
            );
        }
    }

    Ok(())
}

/// Queue an email alert by writing a .eml file.
///
/// For v1, emails are written to `{alert_dir}/email_queue/` as .eml files.
/// A separate process (cron, systemd timer, or sendmail pickup) can
/// deliver them via SMTP. This avoids SMTP library complexity in v1.
///
/// # Arguments
/// * `email` - The recipient email address.
/// * `source_ip` - The threatening IP address.
/// * `score` - The threat score.
/// * `reason` - Human-readable description.
/// * `alert_dir` - Base directory for alert data.
pub fn send_email(
    email: &str,
    source_ip: &IpAddr,
    score: &ThreatScore,
    reason: &str,
    alert_dir: &Path,
) -> ShieldResult<()> {
    let level = scorer::threat_level_label(score);
    let timestamp = chrono::Utc::now();
    let timestamp_rfc2822 = timestamp.format("%a, %d %b %Y %H:%M:%S +0000").to_string();
    let hostname = hostname_string();

    let subject = format!(
        "[SENTINEL Shield] {} - Threat detected from {}",
        level, source_ip
    );

    let body = format!(
        "SENTINEL Shield Alert\n\
         ======================\n\
         \n\
         Timestamp:    {}\n\
         Hostname:     {}\n\
         Source IP:     {}\n\
         Threat Level: {}\n\
         \n\
         Threat Score: {}\n\
         - Velocity:    {:.2}\n\
         - Coverage:    {:.2}\n\
         - Correlation: {:.2}\n\
         \n\
         Reason: {}\n\
         \n\
         ---\n\
         This is an automated alert from SENTINEL Shield.\n\
         Defense only. Watch. Detect. Block. Learn.\n",
        timestamp.to_rfc3339(),
        hostname,
        source_ip,
        level,
        scorer::format_score(score),
        score.velocity,
        score.coverage,
        score.correlation,
        reason,
    );

    let from_addr = format!("sentinel@{}", hostname);
    let eml_content = format!(
        "From: SENTINEL Shield <{}>\r\n\
         To: {}\r\n\
         Subject: {}\r\n\
         Date: {}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         X-SENTINEL-Level: {}\r\n\
         X-SENTINEL-Source-IP: {}\r\n\
         \r\n\
         {}",
        from_addr,
        email,
        subject,
        timestamp_rfc2822,
        level,
        source_ip,
        body,
    );

    // Write to email_queue directory
    let queue_dir = alert_dir.join("email_queue");
    if !queue_dir.exists() {
        std::fs::create_dir_all(&queue_dir)?;
    }

    let filename = format!(
        "sentinel_{}_{}.eml",
        timestamp.format("%Y%m%d_%H%M%S"),
        source_ip.to_string().replace(':', "-"), // IPv6 colons to dashes for filename safety
    );
    let eml_path = queue_dir.join(&filename);

    let mut file = std::fs::File::create(&eml_path)?;
    file.write_all(eml_content.as_bytes())?;
    file.flush()?;

    log::info!(
        "[EMAIL] Queued alert email to {} at {:?}: {} from {}",
        email,
        eml_path,
        level,
        source_ip,
    );

    Ok(())
}

/// Get the system hostname, falling back to "unknown" on error.
fn hostname_string() -> String {
    if cfg!(target_os = "windows") {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    } else {
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScoreWeights;
    use std::net::Ipv4Addr;

    fn test_score() -> ThreatScore {
        ThreatScore::new(
            0.95, 0.72, 0.68,
            &ScoreWeights { velocity: 0.4, coverage: 0.35, correlation: 0.25 },
        )
    }

    #[test]
    fn test_log_alert_creates_file() {
        let dir = std::env::temp_dir().join("sentinel_test_alerts");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("alerts.jsonl");
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let score = test_score();

        let result = log_alert(&log_path, &ip, &score, "Test alert reason");
        assert!(result.is_ok());
        assert!(log_path.exists());

        // Verify JSONL content is valid JSON
        let content = std::fs::read_to_string(&log_path).unwrap();
        let line = content.lines().next().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(parsed["source_ip"], "203.0.113.50");
        assert_eq!(parsed["reason"], "Test alert reason");
        assert!(parsed["timestamp"].is_string());
        assert!(parsed["threat_level"].is_string());

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_log_alert_appends() {
        let dir = std::env::temp_dir().join("sentinel_test_alerts_append");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("alerts.jsonl");
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let score = test_score();

        log_alert(&log_path, &ip, &score, "First alert").unwrap();
        log_alert(&log_path, &ip, &score, "Second alert").unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_webhook_rejects_bad_url() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let score = test_score();

        let result = send_webhook("ftp://bad.example.com", &ip, &score, "test");
        assert!(result.is_err());

        let result2 = send_webhook("not-a-url", &ip, &score, "test");
        assert!(result2.is_err());
    }

    #[test]
    fn test_webhook_accepts_valid_urls() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let score = test_score();

        // These will fail to connect (no server) but should not error on validation
        // The function logs a warning but returns Ok because webhook failures
        // are non-fatal by design.
        let result = send_webhook("https://hooks.example.com/test", &ip, &score, "test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_email_creates_eml() {
        let dir = std::env::temp_dir().join("sentinel_test_email");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let score = test_score();

        let result = send_email("admin@example.com", &ip, &score, "Test threat", &dir);
        assert!(result.is_ok());

        // Verify email_queue directory was created
        let queue_dir = dir.join("email_queue");
        assert!(queue_dir.exists());

        // Verify .eml file was created
        let entries: Vec<_> = std::fs::read_dir(&queue_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);

        let eml_content = std::fs::read_to_string(entries[0].path()).unwrap();
        assert!(eml_content.contains("To: admin@example.com"));
        assert!(eml_content.contains("[SENTINEL Shield]"));
        assert!(eml_content.contains("203.0.113.50"));
        assert!(eml_content.contains("Test threat"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_hostname_returns_something() {
        let h = hostname_string();
        assert!(!h.is_empty());
    }
}

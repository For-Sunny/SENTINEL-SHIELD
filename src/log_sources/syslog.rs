//! Generic syslog parser -- the fallback.
//!
//! Handles standard syslog format: "Mon DD HH:MM:SS hostname process[PID]: message"
//!
//! Copyright (c) 2026 CIPS Corps. All rights reserved.

use crate::log_sources::{EventType, LogEvent, LogSource};
use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static RE_SYSLOG_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$",
    )
    .expect("regex")
});

static RE_IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").expect("regex")
});

static RE_PORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:port|dpt|DPT)[=\s](\d{1,5})").expect("regex")
});

const AUTH_FAILURE_KEYWORDS: &[&str] = &[
    "authentication failure", "auth failure", "failed password",
    "login failed", "invalid password", "bad password",
    "access denied", "permission denied", "unauthorized",
];

const AUTH_SUCCESS_KEYWORDS: &[&str] = &[
    "accepted password", "session opened", "login successful",
    "authenticated", "accepted publickey",
];

const DENIED_KEYWORDS: &[&str] = &[
    "denied", "refused", "blocked", "reject", "dropped",
    "filtered", "firewall", "iptables", "nftables", "ufw",
];

const ERROR_KEYWORDS: &[&str] = &[
    "error", "failed", "failure", "fatal",
    "segfault", "panic", "crash", "abort",
];

pub struct SyslogSource {
    path: PathBuf,
}

impl SyslogSource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl LogSource for SyslogSource {
    fn name(&self) -> &str { "syslog" }

    fn parse_line(&self, line: &str) -> Option<LogEvent> {
        let caps = RE_SYSLOG_HEADER.captures(line)?;
        let month_str = caps.get(1)?.as_str();
        let day_str = caps.get(2)?.as_str();
        let time_str = caps.get(3)?.as_str();
        let process = caps.get(5)?.as_str();
        let message = caps.get(7)?.as_str();

        let timestamp = parse_syslog_timestamp(month_str, day_str, time_str)?;
        let source_ip = extract_first_ip(message)?;

        let target_port = RE_PORT
            .captures(message)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u16>().ok());

        let service_name = process.split('[').next().unwrap_or(process);

        let mut metadata = HashMap::new();
        metadata.insert("process".into(), service_name.into());
        metadata.insert("message".into(), message.into());

        let msg_lower = message.to_lowercase();
        let (event_type, success) = classify_syslog_message(&msg_lower, &mut metadata);

        Some(LogEvent {
            timestamp, source_ip, event_type, target_port,
            target_path: None,
            target_service: Some(service_name.into()),
            success,
            raw_line: line.into(),
            metadata,
        })
    }

    fn watch_path(&self) -> &Path { &self.path }
}

fn classify_syslog_message(
    msg_lower: &str,
    metadata: &mut HashMap<String, String>,
) -> (EventType, bool) {
    for kw in AUTH_FAILURE_KEYWORDS {
        if msg_lower.contains(kw) {
            metadata.insert("classification_reason".into(), format!("keyword: {}", kw));
            return (EventType::AuthFailure, false);
        }
    }
    for kw in AUTH_SUCCESS_KEYWORDS {
        if msg_lower.contains(kw) {
            metadata.insert("classification_reason".into(), format!("keyword: {}", kw));
            return (EventType::AuthSuccess, true);
        }
    }
    for kw in DENIED_KEYWORDS {
        if msg_lower.contains(kw) {
            metadata.insert("classification_reason".into(), format!("keyword: {}", kw));
            return (EventType::PortProbe, false);
        }
    }
    for kw in ERROR_KEYWORDS {
        if msg_lower.contains(kw) {
            metadata.insert("classification_reason".into(), format!("keyword: {}", kw));
            return (EventType::AuthAttempt, false);
        }
    }
    metadata.insert("classification_reason".into(), "ip_present_unclassified".into());
    (EventType::AuthAttempt, false)
}

fn extract_first_ip(message: &str) -> Option<IpAddr> {
    for caps in RE_IPV4.captures_iter(message) {
        if let Some(m) = caps.get(1) {
            if let Ok(ip) = m.as_str().parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => {
                        if v4.is_loopback() || v4.is_unspecified() { continue; }
                        return Some(ip);
                    }
                    IpAddr::V6(v6) => {
                        if v6.is_loopback() || v6.is_unspecified() { continue; }
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

fn parse_syslog_timestamp(month: &str, day: &str, time: &str) -> Option<DateTime<Utc>> {
    let month_num = match month {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
        "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
        "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    };
    let year = Utc::now().year();
    let day_num: u32 = day.trim().parse().ok()?;
    let parts: Vec<&str> = time.split(':').collect();
    if parts.len() != 3 { return None; }
    let hour: u32 = parts[0].parse().ok()?;
    let minute: u32 = parts[1].parse().ok()?;
    let second: u32 = parts[2].parse().ok()?;
    let naive = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month_num, day_num)?,
        chrono::NaiveTime::from_hms_opt(hour, minute, second)?,
    );
    Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SyslogSource {
        SyslogSource::new(PathBuf::from("/var/log/syslog"))
    }

    #[test]
    fn test_firewall_denied() {
        let line = "Jan 15 10:30:00 gateway kernel: [UFW BLOCK] IN=eth0 SRC=45.33.22.11 DST=10.0.0.1 PROTO=TCP DPT=22";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::PortProbe);
        assert_eq!(event.source_ip, "45.33.22.11".parse::<IpAddr>().unwrap());
        assert_eq!(event.target_port, Some(22));
    }

    #[test]
    fn test_auth_failure() {
        let line = "Feb  5 14:00:00 server pam_unix[1234]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.50";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthFailure);
    }

    #[test]
    fn test_session_opened() {
        let line = "Mar 10 08:00:00 web sshd[5678]: session opened for user admin from 10.0.0.100 port 22 authenticated";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthSuccess);
        assert!(event.success);
    }

    #[test]
    fn test_iptables_drop() {
        let line = "Apr 20 16:45:00 fw iptables[9999]: DROPPED: SRC=203.0.113.5 DST=10.0.0.1 DPT=3306";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::PortProbe);
        assert_eq!(event.target_port, Some(3306));
    }

    #[test]
    fn test_no_ip_returns_none() {
        let line = "Jul  4 12:00:00 server systemd[1]: Started some service.";
        assert!(source().parse_line(line).is_none());
    }

    #[test]
    fn test_loopback_only_returns_none() {
        let line = "Aug 10 00:00:00 local app[3333]: error connecting to 127.0.0.1 database";
        assert!(source().parse_line(line).is_none());
    }

    #[test]
    fn test_garbage_returns_none() {
        assert!(source().parse_line("").is_none());
        assert!(source().parse_line("random garbage").is_none());
    }

    #[test]
    fn test_name_and_path() {
        let s = source();
        assert_eq!(s.name(), "syslog");
        assert_eq!(s.watch_path(), Path::new("/var/log/syslog"));
    }
}

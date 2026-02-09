//! Parser for Linux `/var/log/auth.log` (and `/var/log/secure` on RHEL).
//!
//! Handles sshd, sudo, and PAM authentication events.
//! Extracts source IP, username, port, and classifies into EventType.
//!
//! Design: string matching first, regex only when needed for IP/port extraction.
//! A `parse_line` call on a non-matching line costs almost nothing.
//!
//! Copyright (c) 2026 CIPS Corps. All rights reserved.

use crate::log_sources::{EventType, LogEvent, LogSource};
use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Compiled regexes (compiled once, used forever)
// ---------------------------------------------------------------------------

/// "Failed password for <user> from <ip> port <port> ssh2"
static RE_FAILED_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)",
    )
    .expect("regex")
});

/// "Accepted password for <user> from <ip> port <port> ssh2"
/// Also "Accepted publickey for ..."
static RE_ACCEPTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)",
    )
    .expect("regex")
});

/// "Invalid user <user> from <ip> port <port>"
static RE_INVALID_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)(?: port (\d+))?").expect("regex")
});

/// "Connection closed by [authenticating user <user>] <ip> port <port>"
static RE_CONN_CLOSED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"Connection closed by (?:authenticating user (\S+) )?(\d+\.\d+\.\d+\.\d+) port (\d+)",
    )
    .expect("regex")
});

/// "maximum authentication attempts exceeded" / "Too many authentication failures"
static RE_TOO_MANY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:maximum authentication attempts exceeded|[Tt]oo many authentication failures) for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)")
        .expect("regex")
});

/// "Disconnected from [authenticating|invalid] user <user> <ip> port <port>"
static RE_DISCONNECTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"Disconnected from (?:authenticating |invalid )?user (\S+) (\d+\.\d+\.\d+\.\d+) port (\d+)",
    )
    .expect("regex")
});

/// Syslog timestamp header: "Mon DD HH:MM:SS hostname process[PID]:"
static RE_SYSLOG_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$",
    )
    .expect("regex")
});

// ---------------------------------------------------------------------------
// AuthLogSource
// ---------------------------------------------------------------------------

pub struct AuthLogSource {
    path: PathBuf,
}

impl AuthLogSource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl LogSource for AuthLogSource {
    fn name(&self) -> &str {
        "auth.log"
    }

    fn parse_line(&self, line: &str) -> Option<LogEvent> {
        // Quick reject: skip lines without relevant process names.
        if !line.contains("sshd")
            && !line.contains("sudo")
            && !line.contains("pam_unix")
            && !line.contains("systemd-logind")
        {
            return None;
        }

        // Parse the syslog header
        let header = RE_SYSLOG_HEADER.captures(line)?;
        let month_str = header.get(1)?.as_str();
        let day_str = header.get(2)?.as_str();
        let time_str = header.get(3)?.as_str();
        let process = header.get(5)?.as_str();
        let message = header.get(7)?.as_str();

        let timestamp = parse_syslog_timestamp(month_str, day_str, time_str)?;

        let service = if process.starts_with("sshd") {
            "sshd"
        } else if process.starts_with("sudo") {
            "sudo"
        } else {
            process.split('[').next().unwrap_or(process)
        };

        // Try patterns from most specific to least specific.

        // 1. Too many auth failures -> BruteForce
        if let Some(caps) = RE_TOO_MANY.captures(message) {
            let user = caps.get(1)?.as_str();
            let ip: IpAddr = caps.get(2)?.as_str().parse().ok()?;
            let port: u16 = caps.get(3)?.as_str().parse().ok()?;
            let mut metadata = HashMap::new();
            metadata.insert("username".into(), user.into());
            return Some(LogEvent {
                timestamp,
                source_ip: ip,
                event_type: EventType::BruteForce,
                target_port: Some(port),
                target_path: None,
                target_service: Some(service.into()),
                success: false,
                raw_line: line.into(),
                metadata,
            });
        }

        // 2. Failed password
        if let Some(caps) = RE_FAILED_PASSWORD.captures(message) {
            let user = caps.get(1)?.as_str();
            let ip: IpAddr = caps.get(2)?.as_str().parse().ok()?;
            let port: u16 = caps.get(3)?.as_str().parse().ok()?;
            let mut metadata = HashMap::new();
            metadata.insert("username".into(), user.into());
            if message.contains("invalid user") {
                metadata.insert("invalid_user".into(), "true".into());
            }
            return Some(LogEvent {
                timestamp,
                source_ip: ip,
                event_type: EventType::AuthFailure,
                target_port: Some(port),
                target_path: None,
                target_service: Some(service.into()),
                success: false,
                raw_line: line.into(),
                metadata,
            });
        }

        // 3. Accepted password/publickey
        if let Some(caps) = RE_ACCEPTED.captures(message) {
            let user = caps.get(1)?.as_str();
            let ip: IpAddr = caps.get(2)?.as_str().parse().ok()?;
            let port: u16 = caps.get(3)?.as_str().parse().ok()?;
            let mut metadata = HashMap::new();
            metadata.insert("username".into(), user.into());
            if message.contains("publickey") {
                metadata.insert("auth_method".into(), "publickey".into());
            } else {
                metadata.insert("auth_method".into(), "password".into());
            }
            return Some(LogEvent {
                timestamp,
                source_ip: ip,
                event_type: EventType::AuthSuccess,
                target_port: Some(port),
                target_path: None,
                target_service: Some(service.into()),
                success: true,
                raw_line: line.into(),
                metadata,
            });
        }

        // 4. Invalid user
        if let Some(caps) = RE_INVALID_USER.captures(message) {
            let user = caps.get(1)?.as_str();
            let ip: IpAddr = caps.get(2)?.as_str().parse().ok()?;
            let port: u16 = caps
                .get(3)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(22);
            let mut metadata = HashMap::new();
            metadata.insert("username".into(), user.into());
            metadata.insert("invalid_user".into(), "true".into());
            return Some(LogEvent {
                timestamp,
                source_ip: ip,
                event_type: EventType::AuthFailure,
                target_port: Some(port),
                target_path: None,
                target_service: Some(service.into()),
                success: false,
                raw_line: line.into(),
                metadata,
            });
        }

        // 5. Connection closed during auth
        if let Some(caps) = RE_CONN_CLOSED.captures(message) {
            let user = caps.get(1).map(|m| m.as_str().to_string());
            let ip: IpAddr = caps.get(2)?.as_str().parse().ok()?;
            let port: u16 = caps.get(3)?.as_str().parse().ok()?;
            let mut metadata = HashMap::new();
            if let Some(ref u) = user {
                metadata.insert("username".into(), u.clone());
            }
            metadata.insert("reason".into(), "connection_closed".into());
            return Some(LogEvent {
                timestamp,
                source_ip: ip,
                event_type: EventType::AuthAttempt,
                target_port: Some(port),
                target_path: None,
                target_service: Some(service.into()),
                success: false,
                raw_line: line.into(),
                metadata,
            });
        }

        // 6. Disconnected from user
        if let Some(caps) = RE_DISCONNECTED.captures(message) {
            let user = caps.get(1)?.as_str();
            let ip: IpAddr = caps.get(2)?.as_str().parse().ok()?;
            let port: u16 = caps.get(3)?.as_str().parse().ok()?;
            let mut metadata = HashMap::new();
            metadata.insert("username".into(), user.into());
            metadata.insert("reason".into(), "disconnected".into());
            return Some(LogEvent {
                timestamp,
                source_ip: ip,
                event_type: EventType::AuthAttempt,
                target_port: Some(port),
                target_path: None,
                target_service: Some(service.into()),
                success: false,
                raw_line: line.into(),
                metadata,
            });
        }

        None
    }

    fn watch_path(&self) -> &Path {
        &self.path
    }
}

// ---------------------------------------------------------------------------
// Timestamp parsing
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> AuthLogSource {
        AuthLogSource::new(PathBuf::from("/var/log/auth.log"))
    }

    #[test]
    fn test_failed_password() {
        let line = "Jan  5 14:23:01 webserver sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthFailure);
        assert_eq!(event.source_ip, "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(event.target_port, Some(54321));
        assert_eq!(event.metadata.get("username").unwrap(), "admin");
        assert!(!event.success);
    }

    #[test]
    fn test_failed_password_invalid_user() {
        let line = "Feb 12 03:44:55 prod sshd[9999]: Failed password for invalid user oracle from 10.0.0.5 port 22222 ssh2";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthFailure);
        assert_eq!(event.metadata.get("invalid_user").unwrap(), "true");
    }

    #[test]
    fn test_accepted_password() {
        let line = "Mar  1 08:00:00 bastion sshd[1111]: Accepted password for deploy from 172.16.0.50 port 60000 ssh2";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthSuccess);
        assert!(event.success);
        assert_eq!(event.metadata.get("auth_method").unwrap(), "password");
    }

    #[test]
    fn test_accepted_publickey() {
        let line = "Apr 15 12:30:00 server sshd[2222]: Accepted publickey for git from 192.168.10.1 port 44444 ssh2";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthSuccess);
        assert_eq!(event.metadata.get("auth_method").unwrap(), "publickey");
    }

    #[test]
    fn test_invalid_user() {
        let line = "May 20 16:45:30 firewall sshd[3333]: Invalid user testuser from 203.0.113.50 port 12345";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthFailure);
        assert_eq!(event.metadata.get("invalid_user").unwrap(), "true");
    }

    #[test]
    fn test_too_many_auth_failures() {
        let line = "Jun 10 02:15:00 mail sshd[4444]: Too many authentication failures for root from 45.33.22.11 port 55555 ssh2";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::BruteForce);
    }

    #[test]
    fn test_max_auth_attempts() {
        let line = "Jul  3 11:00:00 db sshd[5555]: maximum authentication attempts exceeded for admin from 198.51.100.1 port 33333 ssh2";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::BruteForce);
    }

    #[test]
    fn test_connection_closed() {
        let line = "Aug 22 09:30:45 app sshd[6666]: Connection closed by authenticating user deploy 10.0.0.1 port 40000 [preauth]";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthAttempt);
        assert_eq!(event.metadata.get("username").unwrap(), "deploy");
    }

    #[test]
    fn test_connection_closed_no_user() {
        let line = "Sep  5 18:00:00 web sshd[7777]: Connection closed by 192.168.1.1 port 50000 [preauth]";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthAttempt);
        assert!(!event.metadata.contains_key("username"));
    }

    #[test]
    fn test_disconnected_from_user() {
        let line = "Oct 14 07:22:33 jump sshd[8888]: Disconnected from authenticating user root 10.10.10.10 port 22222 [preauth]";
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.event_type, EventType::AuthAttempt);
        assert_eq!(event.metadata.get("reason").unwrap(), "disconnected");
    }

    #[test]
    fn test_non_ssh_line_returns_none() {
        let line = "Nov  1 12:00:00 server kernel: [12345.678] eth0: link up";
        assert!(source().parse_line(line).is_none());
    }

    #[test]
    fn test_garbage_returns_none() {
        assert!(source().parse_line("").is_none());
        assert!(source().parse_line("not a log line at all").is_none());
        assert!(source().parse_line("sshd but no structure").is_none());
    }

    #[test]
    fn test_malformed_ip_returns_none() {
        let line = "Dec 25 00:00:00 box sshd[9999]: Failed password for root from 999.999.999.999 port 22 ssh2";
        assert!(source().parse_line(line).is_none());
    }

    #[test]
    fn test_name_and_path() {
        let s = source();
        assert_eq!(s.name(), "auth.log");
        assert_eq!(s.watch_path(), Path::new("/var/log/auth.log"));
    }
}

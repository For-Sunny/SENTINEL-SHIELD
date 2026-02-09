//! Parser for Apache/Nginx combined access log format.
//!
//! Format: `IP - - [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "METHOD /path HTTP/x.x" status size "referer" "user-agent"`
//!
//! Copyright (c) 2026 CIPS Corps. All rights reserved.

use crate::log_sources::{EventType, LogEvent, LogSource};
use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static RE_COMBINED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+) "([^"]*)" "([^"]*)""#,
    )
    .expect("regex")
});

static RE_TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})")
        .expect("regex")
});

const TRAVERSAL_PATTERNS: &[&str] = &[
    "../", "..\\", "%2e%2e", "%2e%2e%2f", "%252e%252e",
    "/etc/passwd", "/etc/shadow", "/proc/self",
    "\\windows\\", "\\system32\\",
];

const SQLI_PATTERNS: &[&str] = &[
    "' OR ", "' or ", "' AND ", "' and ",
    "1=1", "1'='1",
    "UNION SELECT", "union select",
    "UNION ALL SELECT", "union all select",
    "DROP TABLE", "drop table",
    "INSERT INTO", "insert into",
    "--", "/*", "*/",
    "SLEEP(", "sleep(",
    "BENCHMARK(", "benchmark(",
    "CHAR(", "char(", "0x",
    "CONCAT(", "concat(",
    "INFORMATION_SCHEMA", "information_schema",
];

const CMDI_PATTERNS: &[&str] = &[
    "; ls", ";ls", "| ls", "|ls",
    ";+ls", "|+ls",
    "; cat ", ";cat ", "| cat ", "|cat ",
    ";+cat+", "|+cat+",
    "; id", ";id", "| id", "|id",
    ";+id", "|+id",
    "; whoami", ";whoami", "| whoami", "|whoami",
    ";+whoami", "|+whoami",
    "$(", "`",
    "| bash", "; bash", "| sh", "; sh",
    "|+bash", ";+bash", "|+sh", ";+sh",
    "| wget ", "; wget ", "| curl ", "; curl ",
    "|+wget+", ";+wget+", "|+curl+", ";+curl+",
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
];

const SUSPICIOUS_PATHS: &[&str] = &[
    "/.env", "/.git", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.htaccess", "/.htpasswd", "/.ssh",
    "/wp-admin", "/wp-login", "/wp-content", "/wp-includes",
    "/phpmyadmin", "/phpMyAdmin", "/pma", "/adminer",
    "/server-status", "/server-info",
    "/xmlrpc.php", "/wp-cron.php",
    "/config.php", "/config.yml", "/config.json",
    "/database.yml", "/db.php",
    "/debug", "/console", "/actuator", "/api/v1",
    "/.well-known", "/cgi-bin", "/manager/html",
    "/solr", "/jenkins", "/.DS_Store",
    "/backup", "/dump", "/sql",
];

const SCANNER_AGENTS: &[&str] = &[
    "sqlmap", "nikto", "nmap", "dirbuster", "gobuster",
    "ffuf", "wfuzz", "burpsuite", "burp", "zap", "owasp",
    "masscan", "nuclei", "httprobe", "subfinder", "amass",
    "whatweb", "wpscan", "joomscan", "acunetix", "nessus",
    "openvas", "arachni", "w3af", "skipfish", "havij",
    "commix", "xerosploit", "metasploit", "hydra", "medusa",
    "patator", "python-requests", "go-http-client",
    "curl/", "wget/", "libwww-perl", "mechanize", "scrapy",
    "zgrab", "censys", "shodan",
];

pub struct WebLogSource {
    path: PathBuf,
    name: String,
}

impl WebLogSource {
    pub fn new(path: PathBuf, name: &str) -> Self {
        Self { path, name: name.to_string() }
    }
}

impl LogSource for WebLogSource {
    fn name(&self) -> &str { &self.name }

    fn parse_line(&self, line: &str) -> Option<LogEvent> {
        let caps = RE_COMBINED.captures(line)?;
        let ip_str = caps.get(1)?.as_str();
        let ts_str = caps.get(2)?.as_str();
        let method = caps.get(3)?.as_str();
        let path = caps.get(4)?.as_str();
        let status_str = caps.get(6)?.as_str();
        let size_str = caps.get(7)?.as_str();
        let referer = caps.get(8)?.as_str();
        let user_agent = caps.get(9)?.as_str();

        let source_ip: IpAddr = ip_str.parse().ok()?;
        let timestamp = parse_combined_timestamp(ts_str)?;
        let status: u16 = status_str.parse().ok()?;

        let mut metadata = HashMap::new();
        metadata.insert("method".into(), method.into());
        metadata.insert("status".into(), status.to_string());
        metadata.insert("user_agent".into(), user_agent.into());
        if size_str != "-" { metadata.insert("size".into(), size_str.into()); }
        if referer != "-" && !referer.is_empty() { metadata.insert("referer".into(), referer.into()); }

        let ua_lower = user_agent.to_lowercase();
        let is_scanner = SCANNER_AGENTS.iter().any(|a| ua_lower.contains(a));
        if is_scanner { metadata.insert("scanner_detected".into(), "true".into()); }

        let path_lower = path.to_lowercase();
        let event_type = classify_request(path, &path_lower, status, is_scanner, &mut metadata);
        let success = (200..400).contains(&status);

        Some(LogEvent {
            timestamp, source_ip, event_type,
            target_port: None,
            target_path: Some(path.into()),
            target_service: Some(self.name.clone()),
            success,
            raw_line: line.into(),
            metadata,
        })
    }

    fn watch_path(&self) -> &Path { &self.path }
}

fn classify_request(
    path: &str, path_lower: &str, status: u16, is_scanner: bool,
    metadata: &mut HashMap<String, String>,
) -> EventType {
    if SQLI_PATTERNS.iter().any(|p| path.contains(p) || path_lower.contains(&p.to_lowercase())) {
        metadata.insert("attack_pattern".into(), "sql_injection".into());
        return EventType::SqlInjection;
    }
    if CMDI_PATTERNS.iter().any(|p| path.contains(p)) {
        metadata.insert("attack_pattern".into(), "command_injection".into());
        return EventType::CommandInjection;
    }
    if TRAVERSAL_PATTERNS.iter().any(|p| path_lower.contains(p)) {
        metadata.insert("attack_pattern".into(), "directory_traversal".into());
        return EventType::DirectoryTraversal;
    }
    if SUSPICIOUS_PATHS.iter().any(|p| path_lower.starts_with(p) || path_lower.contains(p)) {
        metadata.insert("attack_pattern".into(), "suspicious_path".into());
        return EventType::FileAccess;
    }
    if is_scanner { return EventType::ServiceDiscovery; }
    if status >= 400 { return EventType::WebError; }
    EventType::WebRequest
}

fn parse_combined_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    let caps = RE_TIMESTAMP.captures(ts)?;
    let day: u32 = caps.get(1)?.as_str().parse().ok()?;
    let month_str = caps.get(2)?.as_str();
    let year: i32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(5)?.as_str().parse().ok()?;
    let second: u32 = caps.get(6)?.as_str().parse().ok()?;
    let tz_str = caps.get(7)?.as_str();
    let month = match month_str {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
        "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
        "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    };
    let tz_sign: i32 = if tz_str.starts_with('-') { -1 } else { 1 };
    let tz_hours: i32 = tz_str[1..3].parse().ok()?;
    let tz_minutes: i32 = tz_str[3..5].parse().ok()?;
    let tz_offset_seconds = tz_sign * (tz_hours * 3600 + tz_minutes * 60);
    let naive = chrono::NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month, day)?,
        chrono::NaiveTime::from_hms_opt(hour, minute, second)?,
    );
    let fixed_offset = chrono::FixedOffset::east_opt(tz_offset_seconds)?;
    let dt = fixed_offset.from_local_datetime(&naive).single()?;
    Some(dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};

    fn source() -> WebLogSource {
        WebLogSource::new(PathBuf::from("/var/log/nginx/access.log"), "nginx-access")
    }

    fn log_line(ip: &str, path: &str, status: u16, ua: &str) -> String {
        format!(
            r#"{} - - [10/Oct/2024:13:55:36 +0000] "GET {} HTTP/1.1" {} 1234 "-" "{}""#,
            ip, path, status, ua
        )
    }

    #[test]
    fn test_normal_200() {
        let line = log_line("1.2.3.4", "/index.html", 200, "Mozilla/5.0");
        let event = source().parse_line(&line).expect("should parse");
        assert_eq!(event.event_type, EventType::WebRequest);
        assert!(event.success);
    }

    #[test]
    fn test_404_error() {
        let line = log_line("5.6.7.8", "/nonexistent", 404, "Mozilla/5.0");
        let event = source().parse_line(&line).expect("should parse");
        assert_eq!(event.event_type, EventType::WebError);
    }

    #[test]
    fn test_sql_injection_union() {
        let line = log_line("8.8.8.8", "/search?q=1'+UNION+SELECT+*+FROM+users--", 200, "Mozilla/5.0");
        let event = source().parse_line(&line).expect("should parse");
        assert_eq!(event.event_type, EventType::SqlInjection);
    }

    #[test]
    fn test_command_injection() {
        let line = log_line("10.10.10.10", "/ping?host=127.0.0.1;+cat+/etc/passwd", 200, "Mozilla/5.0");
        let event = source().parse_line(&line).expect("should parse");
        assert_eq!(event.event_type, EventType::CommandInjection);
    }

    #[test]
    fn test_directory_traversal() {
        let line = log_line("12.12.12.12", "/../../etc/passwd", 404, "Mozilla/5.0");
        let event = source().parse_line(&line).expect("should parse");
        assert_eq!(event.event_type, EventType::DirectoryTraversal);
    }

    #[test]
    fn test_suspicious_env() {
        let line = log_line("14.14.14.14", "/.env", 200, "Mozilla/5.0");
        let event = source().parse_line(&line).expect("should parse");
        assert_eq!(event.event_type, EventType::FileAccess);
    }

    #[test]
    fn test_scanner_sqlmap() {
        let line = log_line("20.20.20.20", "/", 200, "sqlmap/1.7");
        let event = source().parse_line(&line).expect("should parse");
        assert_eq!(event.event_type, EventType::ServiceDiscovery);
        assert_eq!(event.metadata.get("scanner_detected").unwrap(), "true");
    }

    #[test]
    fn test_scanner_gobuster() {
        let line = log_line("23.23.23.23", "/admin", 403, "gobuster/3.1");
        let event = source().parse_line(&line).expect("should parse");
        assert_eq!(event.event_type, EventType::ServiceDiscovery);
    }

    #[test]
    fn test_timestamp_with_offset() {
        let line = r#"1.1.1.1 - - [25/Dec/2024:23:59:59 -0500] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0""#;
        let event = source().parse_line(line).expect("should parse");
        assert_eq!(event.timestamp.hour(), 4);
        assert_eq!(event.timestamp.day(), 26);
    }

    #[test]
    fn test_garbage_returns_none() {
        assert!(source().parse_line("").is_none());
        assert!(source().parse_line("not a log line").is_none());
    }

    #[test]
    fn test_name_and_path() {
        let s = source();
        assert_eq!(s.name(), "nginx-access");
        assert_eq!(s.watch_path(), Path::new("/var/log/nginx/access.log"));
    }
}

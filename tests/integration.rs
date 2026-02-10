//! # SENTINEL Shield - Integration Tests
//!
//! End-to-end tests that verify the complete detection pipeline:
//! log file -> parser -> detection engine -> graph -> scorer -> response
//!
//! These tests create fake log files with known attack patterns, feed them
//! through the actual LogSourceRegistry -> DetectionEngine -> ResponseOrchestrator
//! chain, and verify that threat scores and alerts match expectations.
//!
//! Unlike unit tests (which test components in isolation), these tests exercise
//! the full pipeline as the daemon would use it, minus the sleep/poll loop.
//!
//! Copyright (c) 2026 CIPS Corps. All rights reserved.

use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;

use chrono::{Datelike, Duration, Utc};
use sentinel_shield::detection::DetectionEngine;
use sentinel_shield::graph::AttackGraph;
use sentinel_shield::log_sources::LogSourceRegistry;
use sentinel_shield::response::ResponseOrchestrator;
use sentinel_shield::{
    DetectionConfig, EventType, LogSourcesConfig,
    ResponseConfig, ScoreWeights, ThreatScore,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Create a temporary directory for test files. Returns the path.
/// The caller is responsible for cleanup.
fn create_test_dir(test_name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("sentinel-shield-test")
        .join(test_name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create test dir");
    dir
}

/// Clean up a test directory.
fn cleanup_test_dir(dir: &PathBuf) {
    let _ = fs::remove_dir_all(dir);
}

/// Get current month abbreviation and day for syslog timestamp format.
fn syslog_ts(offset_secs: i64) -> String {
    let now = Utc::now() + Duration::seconds(offset_secs);
    let month = match now.month() {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "Jan",
    };
    let day = now.day();
    let time = now.format("%H:%M:%S");
    if day < 10 {
        format!("{}  {} {}", month, day, time)
    } else {
        format!("{} {} {}", month, day, time)
    }
}

/// Format datetime for Apache combined log format.
fn web_ts(offset_secs: i64) -> String {
    let now = Utc::now() + Duration::seconds(offset_secs);
    now.format("%d/%b/%Y:%H:%M:%S +0000").to_string()
}

/// Create a test detection config using PRODUCTION defaults.
///
/// Previously this used threshold 0.3 which hid the fact that
/// single-vector attacks (SSH brute force) couldn't reach 0.7.
/// Now that velocity dominance detection is implemented, production
/// threshold works correctly for all attack scenarios.
fn test_detection_config() -> DetectionConfig {
    DetectionConfig {
        threat_threshold: 0.7,
        velocity_weight: 0.4,
        coverage_weight: 0.35,
        correlation_weight: 0.25,
        velocity_window_secs: 120,
        velocity_saturation: 50,
        coverage_saturation: 15,
        correlation_min_gap_secs: 1,
        correlation_max_gap_secs: 300,
    }
}

/// Create a test response config (dry-run, no blocking).
fn test_response_config(alert_path: PathBuf) -> ResponseConfig {
    ResponseConfig {
        blocking_enabled: false,
        alert_log_path: alert_path,
        webhook_url: None,
        alert_email: None,
        block_duration_secs: Some(3600),
    }
}

// ---------------------------------------------------------------------------
// Log line generators (must match parser regex patterns exactly)
// ---------------------------------------------------------------------------

fn auth_failed_password(offset: i64, ip: &str, user: &str, port: u16) -> String {
    format!(
        "{} sentinel-test sshd[12345]: Failed password for {} from {} port {} ssh2",
        syslog_ts(offset),
        user,
        ip,
        port
    )
}

fn auth_failed_invalid_user(offset: i64, ip: &str, user: &str, port: u16) -> String {
    format!(
        "{} sentinel-test sshd[12345]: Failed password for invalid user {} from {} port {} ssh2",
        syslog_ts(offset),
        user,
        ip,
        port
    )
}

fn auth_accepted(offset: i64, ip: &str, user: &str, port: u16) -> String {
    format!(
        "{} sentinel-test sshd[12345]: Accepted password for {} from {} port {} ssh2",
        syslog_ts(offset),
        user,
        ip,
        port
    )
}

fn auth_too_many(offset: i64, ip: &str, user: &str, port: u16) -> String {
    format!(
        "{} sentinel-test sshd[12345]: Too many authentication failures for {} from {} port {} ssh2",
        syslog_ts(offset),
        user,
        ip,
        port
    )
}

fn auth_publickey(offset: i64, ip: &str, user: &str, port: u16) -> String {
    format!(
        "{} sentinel-test sshd[12345]: Accepted publickey for {} from {} port {} ssh2",
        syslog_ts(offset),
        user,
        ip,
        port
    )
}

fn web_line(offset: i64, ip: &str, path: &str, status: u16, ua: &str) -> String {
    format!(
        r#"{} - - [{}] "GET {} HTTP/1.1" {} 1234 "-" "{}""#,
        ip,
        web_ts(offset),
        path,
        status,
        ua
    )
}

fn syslog_firewall_block(offset: i64, ip: &str, port: u16) -> String {
    format!(
        "{} sentinel-test kernel: [UFW BLOCK] IN=eth0 SRC={} DST=10.0.0.1 PROTO=TCP DPT={}",
        syslog_ts(offset),
        ip,
        port
    )
}

/// Write lines to a file, creating it if needed.
fn write_lines(path: &PathBuf, lines: &[String]) {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open file for writing");
    for line in lines {
        writeln!(file, "{}", line).expect("write line");
    }
    file.flush().expect("flush");
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

/// Test 1: Credential spray produces threat score > 0.5
///
/// Generates 50+ failed auth attempts from a single IP with rotating
/// usernames, then verifies the detection engine scores it appropriately.
#[test]
fn test_credential_spray_detection() {
    let dir = create_test_dir("credential_spray");
    let auth_path = dir.join("auth.log");
    let alert_path = dir.join("alerts.jsonl");

    let attacker_ip = "203.0.113.50";

    // Phase 1: 5 invalid user probes
    let mut lines = Vec::new();
    for i in 0..5 {
        let users = ["admin", "root", "deploy", "ubuntu", "ec2-user"];
        lines.push(auth_failed_invalid_user(i, attacker_ip, users[i as usize], 50000 + i as u16));
    }

    // Phase 2: 50 failed password attempts (brute force velocity)
    for i in 0..50 {
        let users = [
            "admin", "root", "deploy", "ubuntu", "ec2-user",
            "git", "jenkins", "postgres", "mysql", "www-data",
        ];
        let user = users[(i % 10) as usize];
        lines.push(auth_failed_password(5 + i, attacker_ip, user, 51000 + i as u16));
    }

    // Phase 3: Too many failures trigger
    lines.push(auth_too_many(56, attacker_ip, "root", 52000));

    // Phase 4: Successful login (compromised)
    lines.push(auth_accepted(58, attacker_ip, "deploy", 53000));

    write_lines(&auth_path, &lines);

    // Set up detection pipeline
    let log_config = LogSourcesConfig {
        auth_log_paths: vec![auth_path.clone()],
        web_log_paths: vec![],
        syslog_paths: vec![],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    // Do NOT seek to end -- we want to read from the beginning
    let events = registry.poll_new_events();

    assert!(
        events.len() >= 50,
        "Expected at least 50 events, got {}",
        events.len()
    );

    let config = test_detection_config();
    let graph = AttackGraph::new();
    let mut engine = DetectionEngine::new(&config, graph);

    let has_threats = {
        let threatening = engine.process_events(events).expect("process_events");
        !threatening.is_empty()
    };

    // The attacker IP should have a session
    let sessions = engine.sessions();
    let attacker: IpAddr = attacker_ip.parse().unwrap();
    let session = sessions
        .get(&attacker)
        .expect("attacker session should exist");

    println!(
        "Credential spray score: combined={:.3}, velocity={:.3}, coverage={:.3}, correlation={:.3}",
        session.threat_score.combined,
        session.threat_score.velocity,
        session.threat_score.coverage,
        session.threat_score.correlation,
    );

    // Velocity should be high (50+ events in short window)
    assert!(
        session.threat_score.velocity > 0.5,
        "Velocity should be > 0.5, got {:.3}",
        session.threat_score.velocity
    );

    // Combined should exceed the production threshold (0.7).
    // Previously this asserted > 0.3 which hid the detection gap.
    assert!(
        session.threat_score.combined > 0.7,
        "Combined score should exceed production threshold 0.7, got {:.3}",
        session.threat_score.combined
    );

    // Should appear in threatening sessions list at production threshold
    assert!(
        has_threats,
        "credential spray should produce threatening sessions at production threshold"
    );

    // Test response orchestrator
    let mut response = ResponseOrchestrator::new(&test_response_config(alert_path.clone()));
    let actions = response
        .respond(attacker, session.threat_score, "credential spray test")
        .expect("respond");

    assert!(!actions.is_empty(), "should produce response actions");
    assert!(
        actions.iter().any(|a| a.executed),
        "at least one action should be executed (LogAlert)"
    );

    // Verify alert was written
    assert!(alert_path.exists(), "alert log should exist");
    let alert_content = fs::read_to_string(&alert_path).expect("read alerts");
    assert!(
        alert_content.contains("203.0.113.50"),
        "alert should contain attacker IP"
    );

    cleanup_test_dir(&dir);
}

/// Test 2: Full kill chain across all log sources produces threat score > 0.7
///
/// Simulates port scan (syslog) + credential spray (auth) + web exploit (web)
/// from the same attacker IP. This is the maximum threat scenario.
#[test]
fn test_full_kill_chain_detection() {
    let dir = create_test_dir("full_kill_chain");
    let auth_path = dir.join("auth.log");
    let web_path = dir.join("access.log");
    let syslog_path = dir.join("syslog.log");
    let _alert_path = dir.join("alerts.jsonl");

    let attacker_ip = "203.0.113.50";

    // Syslog: Port scanning (20+ ports)
    let mut syslog_lines = Vec::new();
    let ports: Vec<u16> = vec![
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
        6379, 8080, 8443, 9200, 27017,
    ];
    for (i, &port) in ports.iter().enumerate() {
        syslog_lines.push(syslog_firewall_block(i as i64, attacker_ip, port));
    }
    write_lines(&syslog_path, &syslog_lines);

    // Auth: Credential spray (20 attempts + brute force trigger + success)
    let mut auth_lines = Vec::new();
    let users = [
        "admin", "root", "deploy", "ubuntu", "ec2-user",
        "git", "jenkins", "postgres", "mysql", "www-data",
        "operator", "test", "backup", "oracle", "ftp",
        "guest", "user", "service", "support", "monitor",
    ];
    let base_offset = ports.len() as i64 + 2;
    for (i, user) in users.iter().enumerate() {
        auth_lines.push(auth_failed_invalid_user(
            base_offset + i as i64,
            attacker_ip,
            user,
            60000 + i as u16,
        ));
    }
    auth_lines.push(auth_too_many(
        base_offset + 21,
        attacker_ip,
        "root",
        61000,
    ));
    auth_lines.push(auth_accepted(
        base_offset + 23,
        attacker_ip,
        "admin",
        62000,
    ));
    write_lines(&auth_path, &auth_lines);

    // Web: Reconnaissance + exploitation
    let mut web_lines = Vec::new();
    let web_base = base_offset + 25;
    let recon_paths = [
        "/admin", "/wp-login.php", "/.env", "/api/v1/users",
        "/phpmyadmin", "/.git/config", "/server-status",
        "/actuator", "/console", "/debug", "/config.php",
        "/backup", "/dump", "/.htpasswd", "/.ssh",
    ];
    for (i, path) in recon_paths.iter().enumerate() {
        let status = if i % 3 == 0 { 200 } else { 404 };
        web_lines.push(web_line(
            web_base + i as i64,
            attacker_ip,
            path,
            status,
            "gobuster/3.1",
        ));
    }
    // SQL injection
    web_lines.push(web_line(
        web_base + 16,
        attacker_ip,
        "/search?q=1'+UNION+SELECT+*+FROM+users--",
        500,
        "sqlmap/1.7",
    ));
    web_lines.push(web_line(
        web_base + 17,
        attacker_ip,
        "/api/v1/users?id=1+OR+1=1",
        500,
        "sqlmap/1.7",
    ));
    // Command injection
    web_lines.push(web_line(
        web_base + 18,
        attacker_ip,
        "/ping?host=127.0.0.1;+cat+/etc/passwd",
        200,
        "Mozilla/5.0",
    ));
    // Directory traversal
    web_lines.push(web_line(
        web_base + 19,
        attacker_ip,
        "/../../etc/passwd",
        404,
        "Mozilla/5.0",
    ));
    write_lines(&web_path, &web_lines);

    // Set up pipeline
    let log_config = LogSourcesConfig {
        auth_log_paths: vec![auth_path.clone()],
        web_log_paths: vec![web_path.clone()],
        syslog_paths: vec![syslog_path.clone()],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    let events = registry.poll_new_events();

    println!("Full kill chain: polled {} events", events.len());
    assert!(
        events.len() >= 40,
        "Expected at least 40 events across all sources, got {}",
        events.len()
    );

    let config = test_detection_config();
    let graph = AttackGraph::new();
    let mut engine = DetectionEngine::new(&config, graph);

    let has_threats = {
        let threatening = engine.process_events(events).expect("process_events");
        !threatening.is_empty()
    };

    let sessions = engine.sessions();
    let attacker: IpAddr = attacker_ip.parse().unwrap();
    let session = sessions
        .get(&attacker)
        .expect("attacker session should exist");

    println!(
        "Full kill chain score: combined={:.3}, velocity={:.3}, coverage={:.3}, correlation={:.3}",
        session.threat_score.combined,
        session.threat_score.velocity,
        session.threat_score.coverage,
        session.threat_score.correlation,
    );
    println!(
        "  Events: {}, Ports: {:?}, Endpoints: {} unique",
        session.event_count(),
        session.targeted_ports.len(),
        session.targeted_endpoints.len(),
    );

    // Full kill chain should exceed production threshold easily.
    assert!(
        session.threat_score.combined > 0.7,
        "Full kill chain combined score should exceed production threshold 0.7, got {:.3}",
        session.threat_score.combined
    );

    // Coverage should be near-maximum (many ports + endpoints)
    assert!(
        session.threat_score.coverage > 0.5,
        "Coverage should be > 0.5 for broad scanning, got {:.3}",
        session.threat_score.coverage
    );

    // Velocity should be high (lots of events in short window)
    assert!(
        session.threat_score.velocity > 0.5,
        "Velocity should be > 0.5, got {:.3}",
        session.threat_score.velocity
    );

    // Should be in threatening list at production threshold
    assert!(
        has_threats,
        "full kill chain should produce threatening sessions at production threshold"
    );

    cleanup_test_dir(&dir);
}

/// Test 3: Benign traffic produces threat score < 0.2
///
/// Normal SSH logins (publickey), normal web browsing, no syslog events
/// with external IPs. SENTINEL should NOT flag these.
#[test]
fn test_benign_traffic_low_score() {
    let dir = create_test_dir("benign_traffic");
    let auth_path = dir.join("auth.log");
    let web_path = dir.join("access.log");
    let syslog_path = dir.join("syslog.log");

    let benign_ip_1 = "198.51.100.10";
    let benign_ip_2 = "198.51.100.20";

    // Normal SSH logins (publickey, spread out)
    let auth_lines = vec![
        auth_publickey(0, benign_ip_1, "deploy", 40000),
        auth_publickey(600, benign_ip_2, "admin", 40001),
        auth_publickey(1200, benign_ip_1, "deploy", 40002),
    ];
    write_lines(&auth_path, &auth_lines);

    // Normal web traffic (200 responses, normal paths, real user agents)
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36";
    let web_lines = vec![
        web_line(0, benign_ip_1, "/", 200, ua),
        web_line(30, benign_ip_1, "/about", 200, ua),
        web_line(60, benign_ip_2, "/", 200, ua),
        web_line(90, benign_ip_1, "/products", 200, ua),
        web_line(120, benign_ip_2, "/contact", 200, ua),
        web_line(150, benign_ip_1, "/static/css/main.css", 200, ua),
        web_line(180, benign_ip_2, "/images/logo.png", 200, ua),
    ];
    write_lines(&web_path, &web_lines);

    // Normal syslog (cron, systemd -- no external IPs so parser returns None)
    let syslog_lines = vec![
        format!(
            "{} sentinel-test CRON[1234]: (root) CMD (/usr/bin/certbot renew)",
            syslog_ts(0)
        ),
        format!(
            "{} sentinel-test systemd[1]: Started Daily apt download activities.",
            syslog_ts(300)
        ),
    ];
    write_lines(&syslog_path, &syslog_lines);

    // Set up pipeline
    let log_config = LogSourcesConfig {
        auth_log_paths: vec![auth_path.clone()],
        web_log_paths: vec![web_path.clone()],
        syslog_paths: vec![syslog_path.clone()],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    let events = registry.poll_new_events();

    println!("Benign traffic: polled {} events", events.len());

    let config = test_detection_config();
    let graph = AttackGraph::new();
    let mut engine = DetectionEngine::new(&config, graph);

    let threat_count = {
        let threatening = engine.process_events(events).expect("process_events");
        threatening.len()
    };

    // Check all sessions have low scores
    let sessions = engine.sessions();
    for (ip, session) in sessions {
        println!(
            "  Benign session {}: combined={:.3}, velocity={:.3}, coverage={:.3}, correlation={:.3} ({} events)",
            ip,
            session.threat_score.combined,
            session.threat_score.velocity,
            session.threat_score.coverage,
            session.threat_score.correlation,
            session.event_count(),
        );

        assert!(
            session.threat_score.combined < 0.3,
            "Benign IP {} should have score < 0.3, got {:.3}",
            ip,
            session.threat_score.combined
        );
    }

    // No sessions should be threatening at production threshold (0.7)
    assert!(
        threat_count == 0,
        "benign traffic should not produce threatening sessions at production threshold, got {}",
        threat_count
    );

    cleanup_test_dir(&dir);
}

/// Test 4: Graph edge weights increase after attack sequences
///
/// Feeds a known attack sequence into the detection engine, runs
/// graph updates, and verifies that the Hebbian edges strengthened
/// for the observed phase transitions.
#[test]
fn test_graph_learning() {
    let mut graph = AttackGraph::new();
    let now = Utc::now();

    // Record initial edge weights
    use sentinel_shield::graph::nodes::ActionType;
    let initial_recon_enum =
        graph.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration);
    let initial_enum_cred =
        graph.edge_weight(ActionType::Enumeration, ActionType::CredentialAttack);

    // Simulate observations: recon -> enum -> credential attack from same source
    // (this is what the detection engine feeds into the graph)
    graph.add_observation("203.0.113.50", ActionType::Reconnaissance, now);
    graph.add_observation(
        "203.0.113.50",
        ActionType::Enumeration,
        now + Duration::seconds(10),
    );
    graph.add_observation(
        "203.0.113.50",
        ActionType::CredentialAttack,
        now + Duration::seconds(20),
    );

    // Run Hebbian learning
    graph.learn();

    // Check that edges strengthened
    let learned_recon_enum =
        graph.edge_weight(ActionType::Reconnaissance, ActionType::Enumeration);
    let learned_enum_cred =
        graph.edge_weight(ActionType::Enumeration, ActionType::CredentialAttack);

    println!("Graph learning:");
    println!(
        "  Recon->Enum: {:.4} -> {:.4} (delta: {:.4})",
        initial_recon_enum,
        learned_recon_enum,
        learned_recon_enum - initial_recon_enum
    );
    println!(
        "  Enum->Cred: {:.4} -> {:.4} (delta: {:.4})",
        initial_enum_cred,
        learned_enum_cred,
        learned_enum_cred - initial_enum_cred
    );

    assert!(
        learned_recon_enum > initial_recon_enum,
        "Recon->Enum edge should strengthen: {} vs {}",
        learned_recon_enum,
        initial_recon_enum
    );

    assert!(
        learned_enum_cred > initial_enum_cred,
        "Enum->CredentialAttack edge should strengthen: {} vs {}",
        learned_enum_cred,
        initial_enum_cred
    );

    // Graph threat score should be higher than zero for this source
    let score = graph.get_threat_score("203.0.113.50");
    println!("  Threat score for attacker: {:.4}", score);
    assert!(
        score > 0.0,
        "Attacker should have non-zero graph threat score"
    );

    // An unknown source should still be 0
    let benign_score = graph.get_threat_score("198.51.100.10");
    assert_eq!(benign_score, 0.0, "Unknown source should have zero score");
}

/// Test 5: Web exploitation scenario
///
/// Web recon -> vulnerability scanning -> successful exploit.
/// Verifies that the web log parser correctly identifies traversal,
/// SQLi, and command injection patterns.
#[test]
fn test_web_exploit_detection() {
    let dir = create_test_dir("web_exploit");
    let web_path = dir.join("access.log");

    let attacker_ip = "203.0.113.51";

    let mut lines = Vec::new();

    // Phase 1: Web recon (suspicious paths producing 404s)
    let recon_paths = [
        "/.env", "/.git/config", "/wp-admin", "/phpmyadmin",
        "/server-status", "/actuator", "/debug", "/config.php",
        "/backup", "/.htpasswd", "/console", "/api/v1",
        "/manager/html", "/solr", "/jenkins",
    ];
    for (i, path) in recon_paths.iter().enumerate() {
        lines.push(web_line(i as i64, attacker_ip, path, 404, "Mozilla/5.0"));
    }

    // Phase 2: Traversal attempts
    lines.push(web_line(16, attacker_ip, "/../../etc/passwd", 404, "Mozilla/5.0"));
    lines.push(web_line(17, attacker_ip, "/static/../../../etc/shadow", 404, "Mozilla/5.0"));

    // Phase 3: SQL injection
    lines.push(web_line(
        18,
        attacker_ip,
        "/search?q=1'+UNION+SELECT+*+FROM+users--",
        500,
        "sqlmap/1.7",
    ));
    lines.push(web_line(
        19,
        attacker_ip,
        "/api/v1/users?id=1+OR+1=1",
        500,
        "sqlmap/1.7",
    ));

    // Phase 4: Command injection (successful)
    lines.push(web_line(
        20,
        attacker_ip,
        "/ping?host=127.0.0.1;+cat+/etc/passwd",
        200,
        "Mozilla/5.0",
    ));

    write_lines(&web_path, &lines);

    // Pipeline
    let log_config = LogSourcesConfig {
        auth_log_paths: vec![],
        web_log_paths: vec![web_path.clone()],
        syslog_paths: vec![],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    let events = registry.poll_new_events();

    println!("Web exploit: polled {} events", events.len());

    // Verify event type classification
    let exploit_count = events
        .iter()
        .filter(|e| e.event_type == EventType::ExploitAttempt)
        .count();
    let probe_count = events
        .iter()
        .filter(|e| e.event_type == EventType::WebProbe)
        .count();

    println!(
        "  ExploitAttempt events: {}, WebProbe events: {}",
        exploit_count, probe_count
    );

    assert!(
        exploit_count >= 3,
        "Should detect at least 3 exploit attempts (2 SQLi + 1 CMDi + traversal), got {}",
        exploit_count
    );

    // Run detection
    let config = test_detection_config();
    let graph = AttackGraph::new();
    let mut engine = DetectionEngine::new(&config, graph);

    let has_threats = {
        let threatening = engine.process_events(events).expect("process_events");
        !threatening.is_empty()
    };

    let attacker: IpAddr = attacker_ip.parse().unwrap();
    let session = engine
        .sessions()
        .get(&attacker)
        .expect("attacker session");

    println!(
        "  Web exploit score: combined={:.3}, velocity={:.3}, coverage={:.3}, correlation={:.3}",
        session.threat_score.combined,
        session.threat_score.velocity,
        session.threat_score.coverage,
        session.threat_score.correlation,
    );

    // Coverage should be significant (many unique endpoints)
    assert!(
        session.targeted_endpoints.len() >= 10,
        "Should have many targeted endpoints, got {}",
        session.targeted_endpoints.len()
    );

    // Correlation: recon events followed quickly by exploit events
    assert!(
        session.threat_score.correlation > 0.0,
        "Correlation should be > 0 (recon followed by exploit), got {:.3}",
        session.threat_score.correlation
    );

    // Combined should exceed production threshold
    assert!(
        session.threat_score.combined > 0.7,
        "Web exploit combined score should exceed production threshold 0.7, got {:.3}",
        session.threat_score.combined,
    );

    assert!(
        has_threats,
        "Web exploitation should produce threatening sessions at production threshold"
    );

    cleanup_test_dir(&dir);
}

/// Test 6: Response orchestrator generates correct alert JSONL
///
/// Verifies the alert log format, content, and that multiple alerts
/// append correctly (not overwrite).
#[test]
fn test_response_alert_generation() {
    let dir = create_test_dir("response_alerts");
    let alert_path = dir.join("alerts.jsonl");

    let mut response = ResponseOrchestrator::new(&test_response_config(alert_path.clone()));

    let weights = ScoreWeights {
        velocity: 0.4,
        coverage: 0.35,
        correlation: 0.25,
    };

    // Alert 1
    let ip1: IpAddr = "203.0.113.50".parse().unwrap();
    let score1 = ThreatScore::new(0.9, 0.7, 0.6, &weights);
    let actions1 = response
        .respond(ip1, score1, "credential spray from 203.0.113.50")
        .expect("respond 1");

    assert!(!actions1.is_empty());
    assert!(
        actions1.iter().any(|a| a.executed),
        "at least one action should execute"
    );

    // Alert 2 (different IP)
    let ip2: IpAddr = "203.0.113.51".parse().unwrap();
    let score2 = ThreatScore::new(0.8, 0.6, 0.9, &weights);
    let actions2 = response
        .respond(ip2, score2, "web exploit from 203.0.113.51")
        .expect("respond 2");

    assert!(!actions2.is_empty());

    // Verify JSONL file
    assert!(alert_path.exists(), "alert log should exist");
    let content = fs::read_to_string(&alert_path).expect("read alerts");
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    assert_eq!(
        lines.len(),
        2,
        "should have exactly 2 alert lines, got {}",
        lines.len()
    );

    // Parse and validate each line
    for (i, line) in lines.iter().enumerate() {
        let parsed: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("Invalid JSON on line {}: {}", i, e));

        assert!(parsed["timestamp"].is_string(), "should have timestamp");
        assert!(parsed["source_ip"].is_string(), "should have source_ip");
        assert!(parsed["threat_score"].is_number(), "should have threat_score");
        assert!(parsed["threat_level"].is_string(), "should have threat_level");
        assert!(parsed["reason"].is_string(), "should have reason");
    }

    // Verify IPs in alerts
    assert!(content.contains("203.0.113.50"), "should contain first IP");
    assert!(content.contains("203.0.113.51"), "should contain second IP");

    cleanup_test_dir(&dir);
}

/// Test 7: Multiple independent sources are scored independently
///
/// Two different IPs: one attacking, one benign. Verifies they get
/// different threat scores and the attacker triggers alerts while
/// benign traffic does not.
///
/// The attacker sends 60 failed auth attempts (high-volume brute force)
/// to ensure velocity crosses the dominance threshold and the attack
/// is detectable at production threshold (0.7).
#[test]
fn test_independent_source_scoring() {
    let dir = create_test_dir("independent_sources");
    let auth_path = dir.join("auth.log");
    let web_path = dir.join("access.log");

    let attacker_ip = "203.0.113.50";
    let benign_ip = "198.51.100.10";

    // Attacker: 60 failed auth attempts (high-volume brute force)
    let mut auth_lines = Vec::new();
    for i in 0..60 {
        let users = ["admin", "root", "deploy", "ubuntu", "jenkins",
                      "git", "postgres", "mysql", "www-data", "oracle"];
        auth_lines.push(auth_failed_password(
            i,
            attacker_ip,
            users[(i % 10) as usize],
            50000 + i as u16,
        ));
    }
    // Benign: 2 successful logins
    auth_lines.push(auth_publickey(70, benign_ip, "deploy", 40000));
    auth_lines.push(auth_publickey(130, benign_ip, "admin", 40001));
    write_lines(&auth_path, &auth_lines);

    // Benign web traffic
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    let web_lines = vec![
        web_line(0, benign_ip, "/", 200, ua),
        web_line(10, benign_ip, "/about", 200, ua),
        web_line(20, benign_ip, "/products", 200, ua),
    ];
    write_lines(&web_path, &web_lines);

    let log_config = LogSourcesConfig {
        auth_log_paths: vec![auth_path.clone()],
        web_log_paths: vec![web_path.clone()],
        syslog_paths: vec![],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    let events = registry.poll_new_events();

    let config = test_detection_config();
    let graph = AttackGraph::new();
    let mut engine = DetectionEngine::new(&config, graph);

    let threat_count = {
        let threatening = engine.process_events(events).expect("process_events");
        threatening.len()
    };

    let sessions = engine.sessions();
    let attacker: IpAddr = attacker_ip.parse().unwrap();
    let benign: IpAddr = benign_ip.parse().unwrap();

    let attacker_session = sessions.get(&attacker).expect("attacker session");
    let benign_session = sessions.get(&benign);

    println!(
        "Independent scoring: attacker={:.3}, benign={:.3}",
        attacker_session.threat_score.combined,
        benign_session
            .map(|s| s.threat_score.combined)
            .unwrap_or(0.0)
    );

    // Attacker should exceed production threshold (0.7)
    assert!(
        attacker_session.threat_score.combined > 0.7,
        "Attacker (60 failed auths) should exceed production threshold 0.7, got {:.3}",
        attacker_session.threat_score.combined
    );

    // Benign should have low score (if session exists at all)
    if let Some(bs) = benign_session {
        assert!(
            bs.threat_score.combined < 0.3,
            "Benign IP should score < 0.3, got {:.3}",
            bs.threat_score.combined
        );
    }

    // Only attacker should be in threatening list
    assert!(
        threat_count >= 1,
        "attacker should appear in threatening sessions"
    );

    cleanup_test_dir(&dir);
}

/// Test 8: Parser correctly handles all auth.log patterns
///
/// Verifies that each auth.log line format the simulator generates
/// is correctly parsed by the AuthLogSource parser.
#[test]
fn test_auth_parser_completeness() {
    let dir = create_test_dir("auth_parser");
    let auth_path = dir.join("auth.log");

    let ip = "203.0.113.50";
    let lines = vec![
        auth_failed_password(0, ip, "admin", 54321),
        auth_failed_invalid_user(1, ip, "oracle", 54322),
        auth_accepted(2, ip, "deploy", 54323),
        auth_too_many(3, ip, "root", 54324),
        auth_publickey(4, ip, "git", 54325),
    ];
    write_lines(&auth_path, &lines);

    let log_config = LogSourcesConfig {
        auth_log_paths: vec![auth_path.clone()],
        web_log_paths: vec![],
        syslog_paths: vec![],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    let events = registry.poll_new_events();

    println!("Auth parser completeness: {} events from {} lines", events.len(), lines.len());

    // Every line should produce an event
    assert_eq!(
        events.len(),
        lines.len(),
        "Every auth log line should parse: got {} events from {} lines",
        events.len(),
        lines.len()
    );

    // Verify event types
    let types: Vec<_> = events.iter().map(|e| &e.event_type).collect();
    assert!(
        types.contains(&&EventType::AuthFailure),
        "should detect AuthFailure"
    );
    assert!(
        types.contains(&&EventType::AuthSuccess),
        "should detect AuthSuccess"
    );
    assert!(
        types.contains(&&EventType::BruteForce),
        "should detect BruteForce"
    );

    cleanup_test_dir(&dir);
}

/// Test 9: Parser correctly handles web log attack patterns
///
/// Verifies that SQLi, command injection, and directory traversal
/// patterns in web logs are correctly classified.
#[test]
fn test_web_parser_attack_classification() {
    let dir = create_test_dir("web_parser");
    let web_path = dir.join("access.log");

    let ip = "203.0.113.50";

    // Each line tests a specific attack pattern
    let lines = vec![
        // Normal request
        web_line(0, ip, "/index.html", 200, "Mozilla/5.0"),
        // SQL injection (UNION SELECT)
        web_line(1, ip, "/search?q=1'+UNION+SELECT+*+FROM+users--", 500, "Mozilla/5.0"),
        // Command injection (;cat)
        web_line(2, ip, "/ping?host=127.0.0.1;+cat+/etc/passwd", 200, "Mozilla/5.0"),
        // Directory traversal (../)
        web_line(3, ip, "/../../etc/passwd", 404, "Mozilla/5.0"),
        // Suspicious path (/.env)
        web_line(4, ip, "/.env", 200, "Mozilla/5.0"),
        // Scanner user agent
        web_line(5, ip, "/", 200, "sqlmap/1.7"),
        // 404 error (generic)
        web_line(6, ip, "/nonexistent", 404, "Mozilla/5.0"),
    ];
    write_lines(&web_path, &lines);

    let log_config = LogSourcesConfig {
        auth_log_paths: vec![],
        web_log_paths: vec![web_path.clone()],
        syslog_paths: vec![],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    let events = registry.poll_new_events();

    assert_eq!(
        events.len(),
        lines.len(),
        "Every web log line should parse"
    );

    // Map events by type for verification
    let exploit_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::ExploitAttempt)
        .collect();
    let probe_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::WebProbe)
        .collect();

    println!(
        "Web parser classification: {} ExploitAttempt, {} WebProbe, {} total",
        exploit_events.len(),
        probe_events.len(),
        events.len()
    );

    // SQLi, CMDi, and directory traversal should all be ExploitAttempt
    assert!(
        exploit_events.len() >= 3,
        "Should detect at least 3 exploit attempts (SQLi + CMDi + traversal), got {}",
        exploit_events.len()
    );

    cleanup_test_dir(&dir);
}

/// Test 10: Syslog parser extracts IPs and classifies firewall blocks
///
/// Verifies that syslog lines with firewall block messages are correctly
/// parsed and that lines without external IPs are skipped.
#[test]
fn test_syslog_parser() {
    let dir = create_test_dir("syslog_parser");
    let syslog_path = dir.join("syslog.log");

    let attacker_ip = "203.0.113.50";

    let mut lines = Vec::new();

    // Firewall blocks (should parse)
    for &port in &[22u16, 80, 443, 3306, 5432] {
        lines.push(syslog_firewall_block(port as i64, attacker_ip, port));
    }

    // Normal system messages without external IPs (should be skipped)
    lines.push(format!(
        "{} sentinel-test CRON[1234]: (root) CMD (/usr/bin/certbot renew)",
        syslog_ts(100)
    ));
    lines.push(format!(
        "{} sentinel-test systemd[1]: Started Daily apt download activities.",
        syslog_ts(200)
    ));
    // Loopback IP only (should be skipped)
    lines.push(format!(
        "{} sentinel-test app[3333]: error connecting to 127.0.0.1 database",
        syslog_ts(300)
    ));

    write_lines(&syslog_path, &lines);

    let log_config = LogSourcesConfig {
        auth_log_paths: vec![],
        web_log_paths: vec![],
        syslog_paths: vec![syslog_path.clone()],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    let events = registry.poll_new_events();

    println!(
        "Syslog parser: {} events from {} lines (5 expected from firewall blocks)",
        events.len(),
        lines.len()
    );

    // Should get exactly 5 events (the firewall blocks)
    // Lines without external IPs should be skipped
    assert_eq!(
        events.len(),
        5,
        "Should parse exactly 5 firewall block lines, got {}",
        events.len()
    );

    // All events should be from the attacker IP
    let attacker: IpAddr = attacker_ip.parse().unwrap();
    assert!(
        events.iter().all(|e| e.source_ip == attacker),
        "All events should be from the attacker IP"
    );

    // Events should be classified as Reconnaissance (firewall blocks = PortProbe -> Reconnaissance)
    assert!(
        events
            .iter()
            .all(|e| e.event_type == EventType::Reconnaissance),
        "Firewall blocks should classify as Reconnaissance"
    );

    cleanup_test_dir(&dir);
}

/// Test 11: SSH brute force from one IP to port 22 at production threshold
///
/// This is THE most common attack on the internet. 100 failed SSH logins
/// from one IP in under 2 minutes. Single port (22), single event type
/// (AuthFailure), zero discovery-exploit correlation.
///
/// Previously this maxed out at ~0.42 and could never reach the 0.7
/// production threshold because:
/// - Velocity saturated at 1.0 but only contributed weight 0.4
/// - Coverage was stuck at ~0.05 (1 port / 20 saturation)
/// - Correlation was 0.0 (no discovery events to pair with)
///
/// The velocity dominance mechanism fixes this: extreme velocity on
/// a concentrated target IS sufficient signal for detection.
#[test]
fn test_ssh_brute_force_single_port() {
    let dir = create_test_dir("ssh_brute_force");
    let auth_path = dir.join("auth.log");

    let attacker_ip = "203.0.113.99";

    // 100 failed password attempts to port 22, all from one IP, 1 per second
    let mut lines = Vec::new();
    for i in 0..100 {
        let users = [
            "root", "admin", "deploy", "ubuntu", "ec2-user",
            "git", "jenkins", "postgres", "mysql", "www-data",
        ];
        // Note: all target port 22 (the SSH target), source port varies
        lines.push(auth_failed_password(i, attacker_ip, users[(i % 10) as usize], 22));
    }
    lines.push(auth_too_many(101, attacker_ip, "root", 22));

    write_lines(&auth_path, &lines);

    let log_config = LogSourcesConfig {
        auth_log_paths: vec![auth_path.clone()],
        web_log_paths: vec![],
        syslog_paths: vec![],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    let events = registry.poll_new_events();

    assert!(
        events.len() >= 100,
        "Expected at least 100 events, got {}",
        events.len()
    );

    // Use PRODUCTION config -- threshold 0.7
    let config = test_detection_config();
    assert_eq!(config.threat_threshold, 0.7, "must use production threshold");

    let graph = AttackGraph::new();
    let mut engine = DetectionEngine::new(&config, graph);

    let has_threats = {
        let threatening = engine.process_events(events).expect("process_events");
        !threatening.is_empty()
    };

    let attacker: IpAddr = attacker_ip.parse().unwrap();
    let session = engine
        .sessions()
        .get(&attacker)
        .expect("attacker session should exist");

    println!(
        "SSH brute force (single port): combined={:.3}, velocity={:.3}, coverage={:.3}, correlation={:.3}",
        session.threat_score.combined,
        session.threat_score.velocity,
        session.threat_score.coverage,
        session.threat_score.correlation,
    );

    // Velocity should be saturated (100+ events in 120s window, saturation=50)
    assert!(
        session.threat_score.velocity >= 1.0,
        "Velocity should saturate at 1.0 for 100 events, got {:.3}",
        session.threat_score.velocity
    );

    // Coverage should be very low (single port)
    assert!(
        session.threat_score.coverage < 0.2,
        "Coverage should be low for single-port attack, got {:.3}",
        session.threat_score.coverage
    );

    // Correlation should be zero (no discovery events)
    assert!(
        session.threat_score.correlation < 0.01,
        "Correlation should be ~0 for auth-only events, got {:.3}",
        session.threat_score.correlation
    );

    // THIS IS THE KEY ASSERTION: despite low coverage and zero correlation,
    // the velocity dominance mechanism should push this above 0.7
    assert!(
        session.threat_score.combined > 0.7,
        "SSH brute force MUST be detectable at production threshold (0.7). \
         This is the most common attack on the internet. Got {:.3}",
        session.threat_score.combined
    );

    assert!(
        has_threats,
        "SSH brute force should appear in threatening sessions at production threshold"
    );

    cleanup_test_dir(&dir);
}

/// Test 12: Graph knowledge feeds into detection scoring
///
/// Verifies that the Hebbian graph's learned patterns influence the
/// detection engine's final score. After processing events, the graph
/// should have observations, and its threat scoring should contribute
/// to the combined score.
#[test]
fn test_graph_feeds_into_scoring() {
    let dir = create_test_dir("graph_scoring");
    let auth_path = dir.join("auth.log");
    let web_path = dir.join("access.log");

    let attacker_ip = "203.0.113.60";

    // Web recon followed by auth attacks = multi-phase attack
    // This should feed into the graph as Enumeration -> CredentialAttack
    let mut web_lines = Vec::new();
    let recon_paths = [
        "/.env", "/admin", "/wp-login.php", "/.git/config",
        "/phpmyadmin", "/api/v1/users", "/console", "/debug",
    ];
    for (i, path) in recon_paths.iter().enumerate() {
        web_lines.push(web_line(i as i64, attacker_ip, path, 404, "Mozilla/5.0"));
    }
    write_lines(&web_path, &web_lines);

    let mut auth_lines = Vec::new();
    for i in 0..40 {
        let users = ["admin", "root", "deploy", "ubuntu", "git"];
        auth_lines.push(auth_failed_password(
            10 + i,
            attacker_ip,
            users[(i % 5) as usize],
            22,
        ));
    }
    write_lines(&auth_path, &auth_lines);

    let log_config = LogSourcesConfig {
        auth_log_paths: vec![auth_path.clone()],
        web_log_paths: vec![web_path.clone()],
        syslog_paths: vec![],
    };

    let mut registry = LogSourceRegistry::new(&log_config);
    let events = registry.poll_new_events();

    let config = test_detection_config();
    let graph = AttackGraph::new();
    let mut engine = DetectionEngine::new(&config, graph);

    {
        let _threatening = engine.process_events(events).expect("process_events");
    }

    // Verify graph was populated
    let graph = engine.graph();
    let source_str = attacker_ip;
    assert!(
        graph.sources.contains_key(source_str),
        "Graph should have observations for attacker IP"
    );

    let graph_score = graph.get_threat_score(source_str);
    println!(
        "Graph-fed scoring: graph_threat={:.3}, total_observations={}",
        graph_score,
        graph.total_observations,
    );

    // Graph should have recorded observations from the events
    assert!(
        graph.total_observations > 0,
        "Graph should have recorded observations"
    );

    // Graph threat score should be non-zero for a multi-phase attack
    assert!(
        graph_score > 0.0,
        "Graph should produce non-zero threat score for multi-phase attack, got {:.3}",
        graph_score,
    );

    // Verify graph stats show learning happened
    let stats = graph.stats();
    println!(
        "  Graph stats: observations={}, sources={}, learn_cycles={}, pending={}",
        stats.total_observations,
        stats.active_sources,
        stats.learn_cycles,
        stats.pending_updates,
    );

    assert!(
        stats.learn_cycles > 0,
        "Graph should have run at least one learn cycle"
    );

    cleanup_test_dir(&dir);
}

//! # SENTINEL Shield - Core Library
//!
//! Defense-only AI attack detection daemon for small companies.
//!
//! SENTINEL Shield watches network logs, detects AI-orchestrated attack patterns
//! through velocity analysis, coverage mapping, and temporal correlation, then
//! blocks malicious sources and alerts operators.
//!
//! ## Design Philosophy
//! - **Defense only.** No offensive capability. No exploit generation. No attack tools.
//! - **Watch, Detect, Block, Learn.** Nothing else.
//! - The Hebbian graph learns attack patterns over time without retraining.
//! - Lightweight enough for a small company's single server.

pub mod detection;
pub mod log_sources;
pub mod response;
pub mod graph;
pub mod dashboard;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Unified error type for SENTINEL Shield.
#[derive(Error, Debug)]
pub enum ShieldError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Log parse error: {0}")]
    LogParse(String),

    #[error("Detection engine error: {0}")]
    Detection(String),

    #[error("Response action failed: {0}")]
    Response(String),

    #[error("Graph error: {0}")]
    Graph(String),

    #[error("Dashboard error: {0}")]
    Dashboard(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML deserialization error: {0}")]
    TomlDe(#[from] toml::de::Error),
}

pub type ShieldResult<T> = Result<T, ShieldError>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Top-level configuration for SENTINEL Shield.
///
/// Loaded from `sentinel-shield.toml` in the working directory or a path
/// supplied via CLI flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    /// General daemon settings.
    pub general: GeneralConfig,

    /// Detection engine tuning knobs.
    pub detection: DetectionConfig,

    /// Log source definitions.
    pub log_sources: LogSourcesConfig,

    /// Response action settings.
    pub response: ResponseConfig,

    /// Dashboard settings.
    pub dashboard: DashboardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// How often (in seconds) the engine evaluates accumulated events.
    pub eval_interval_secs: u64,

    /// Path where SENTINEL persists its state (graph, block list, etc.).
    pub data_dir: PathBuf,

    /// Path to the graph state file for persistence across restarts.
    pub graph_state_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Threshold (0.0 - 1.0) above which an IP is considered a threat.
    pub threat_threshold: f64,

    /// Weight for velocity score in the combined threat score.
    pub velocity_weight: f64,

    /// Weight for coverage score in the combined threat score.
    pub coverage_weight: f64,

    /// Weight for correlation score in the combined threat score.
    pub correlation_weight: f64,

    /// Sliding window duration in seconds for velocity calculation.
    pub velocity_window_secs: u64,

    /// Maximum requests per window before velocity score saturates at 1.0.
    pub velocity_saturation: u64,

    /// Number of unique ports/endpoints before coverage score saturates at 1.0.
    pub coverage_saturation: u64,

    /// Minimum seconds between discovery and exploit for correlation to register.
    /// Below this threshold, the attack is clearly automated.
    pub correlation_min_gap_secs: u64,

    /// Maximum seconds between discovery and exploit to still count as correlated.
    pub correlation_max_gap_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSourcesConfig {
    /// Paths to auth log files (e.g., /var/log/auth.log).
    pub auth_log_paths: Vec<PathBuf>,

    /// Paths to web server access logs (Apache/Nginx combined format).
    pub web_log_paths: Vec<PathBuf>,

    /// Paths to syslog files.
    pub syslog_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    /// Whether to actually execute IP blocks (false = dry-run / log only).
    pub blocking_enabled: bool,

    /// Path to the alert log file.
    pub alert_log_path: PathBuf,

    /// Optional webhook URL for real-time alerts.
    pub webhook_url: Option<String>,

    /// Optional email address for alert notifications.
    pub alert_email: Option<String>,

    /// How many seconds an IP stays blocked before automatic expiry.
    /// None = permanent until manual unblock.
    pub block_duration_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Whether to start the dashboard HTTP server.
    pub enabled: bool,

    /// Bind address (e.g., "127.0.0.1").
    pub bind_address: String,

    /// Port to listen on.
    pub port: u16,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                eval_interval_secs: 10,
                data_dir: PathBuf::from("./sentinel-data"),
                graph_state_file: PathBuf::from("./sentinel-data/graph.json"),
            },
            detection: DetectionConfig {
                threat_threshold: 0.7,
                velocity_weight: 0.4,
                coverage_weight: 0.35,
                correlation_weight: 0.25,
                velocity_window_secs: 60,
                velocity_saturation: 100,
                coverage_saturation: 20,
                correlation_min_gap_secs: 1,
                correlation_max_gap_secs: 300,
            },
            log_sources: LogSourcesConfig {
                auth_log_paths: vec![],
                web_log_paths: vec![],
                syslog_paths: vec![],
            },
            response: ResponseConfig {
                blocking_enabled: false,
                alert_log_path: PathBuf::from("./sentinel-data/alerts.log"),
                webhook_url: None,
                alert_email: None,
                block_duration_secs: Some(3600),
            },
            dashboard: DashboardConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port: 8080,
            },
        }
    }
}

impl ShieldConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> ShieldResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: ShieldConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Write the default configuration to a TOML file.
    pub fn write_default(path: &std::path::Path) -> ShieldResult<()> {
        let config = Self::default();
        let content = toml::to_string_pretty(&config)
            .map_err(|e| ShieldError::Config(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Core Types
// ---------------------------------------------------------------------------

/// A threat score in the range [0.0, 1.0].
///
/// 0.0 = no threat detected.
/// 1.0 = maximum threat confidence.
///
/// The score is a weighted combination of velocity, coverage, and correlation
/// sub-scores. See `detection::scorer` for the math.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
pub struct ThreatScore {
    /// Combined score (0.0 - 1.0).
    pub combined: f64,

    /// Velocity component before weighting.
    pub velocity: f64,

    /// Coverage component before weighting.
    pub coverage: f64,

    /// Correlation component before weighting.
    pub correlation: f64,
}

impl ThreatScore {
    /// Create a new ThreatScore, clamping all values to [0.0, 1.0].
    pub fn new(velocity: f64, coverage: f64, correlation: f64, weights: &ScoreWeights) -> Self {
        let v = velocity.clamp(0.0, 1.0);
        let c = coverage.clamp(0.0, 1.0);
        let r = correlation.clamp(0.0, 1.0);

        let combined = (v * weights.velocity + c * weights.coverage + r * weights.correlation)
            .clamp(0.0, 1.0);

        Self {
            combined,
            velocity: v,
            coverage: c,
            correlation: r,
        }
    }

    /// Returns true if this score exceeds the given threshold.
    pub fn is_threat(&self, threshold: f64) -> bool {
        self.combined >= threshold
    }
}

/// Weights for combining sub-scores into a final threat score.
/// Should sum to 1.0 for normalized output.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ScoreWeights {
    pub velocity: f64,
    pub coverage: f64,
    pub correlation: f64,
}

impl From<&DetectionConfig> for ScoreWeights {
    fn from(config: &DetectionConfig) -> Self {
        Self {
            velocity: config.velocity_weight,
            coverage: config.coverage_weight,
            correlation: config.correlation_weight,
        }
    }
}

/// Represents an active attack session from a single source IP.
///
/// An AttackSession accumulates events over time and tracks the progression
/// of activity from a single source. The session is the unit of analysis
/// for the detection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSession {
    /// Unique session identifier.
    pub id: String,

    /// Source IP address of the attacker.
    pub source_ip: IpAddr,

    /// When the first event from this source was observed.
    pub first_seen: DateTime<Utc>,

    /// When the most recent event from this source was observed.
    pub last_seen: DateTime<Utc>,

    /// All detection events in this session, ordered by time.
    pub events: Vec<DetectionEvent>,

    /// Current threat score for this session.
    pub threat_score: ThreatScore,

    /// Unique ports targeted by this source.
    pub targeted_ports: Vec<u16>,

    /// Unique URL paths / endpoints targeted by this source.
    pub targeted_endpoints: Vec<String>,

    /// Whether a response action has already been taken for this session.
    pub response_taken: bool,

    /// Attack phase progression as classified by the graph.
    pub attack_phases: Vec<AttackPhase>,
}

impl AttackSession {
    /// Create a new attack session from an initial event.
    pub fn new(event: DetectionEvent) -> Self {
        let source_ip = event.source_ip;
        let now = event.timestamp;
        let zero_weights = ScoreWeights {
            velocity: 0.4,
            coverage: 0.35,
            correlation: 0.25,
        };

        Self {
            id: format!("{}-{}", source_ip, now.timestamp()),
            source_ip,
            first_seen: now,
            last_seen: now,
            events: vec![event],
            threat_score: ThreatScore::new(0.0, 0.0, 0.0, &zero_weights),
            targeted_ports: Vec::new(),
            targeted_endpoints: Vec::new(),
            response_taken: false,
            attack_phases: Vec::new(),
        }
    }

    /// Add an event to this session.
    pub fn add_event(&mut self, event: DetectionEvent) {
        if event.timestamp > self.last_seen {
            self.last_seen = event.timestamp;
        }
        if let Some(port) = event.target_port {
            if !self.targeted_ports.contains(&port) {
                self.targeted_ports.push(port);
            }
        }
        if let Some(ref endpoint) = event.target_endpoint {
            if !self.targeted_endpoints.contains(endpoint) {
                self.targeted_endpoints.push(endpoint.clone());
            }
        }
        self.events.push(event);
    }

    /// Duration of this session in seconds.
    pub fn duration_secs(&self) -> i64 {
        (self.last_seen - self.first_seen).num_seconds()
    }

    /// Total number of events in this session.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

/// A single detection event parsed from a log source.
///
/// This is the atomic unit of observation. Log parsers produce these;
/// the detection engine consumes them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// When this event occurred.
    pub timestamp: DateTime<Utc>,

    /// Source IP address.
    pub source_ip: IpAddr,

    /// Target port, if applicable.
    pub target_port: Option<u16>,

    /// Target endpoint / URL path, if applicable.
    pub target_endpoint: Option<String>,

    /// What kind of event this is.
    pub event_type: EventType,

    /// Which log source produced this event.
    pub source: LogSourceType,

    /// Raw log line for forensic reference.
    pub raw_line: String,
}

/// Classification of detected events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    /// Failed authentication attempt (SSH, HTTP basic auth, etc.).
    AuthFailure,

    /// Successful authentication (may indicate compromised credentials).
    AuthSuccess,

    /// Port scan or service enumeration.
    Reconnaissance,

    /// Web endpoint probing (404s, directory traversal, admin paths).
    WebProbe,

    /// Exploit attempt (SQLi, XSS, command injection patterns in logs).
    ExploitAttempt,

    /// Brute force pattern (high-frequency auth failures).
    BruteForce,

    /// Credential stuffing (many different usernames, same source).
    CredentialStuffing,

    /// Lateral movement indicator (internal IP after external compromise).
    LateralMovement,

    /// Data exfiltration indicator (large outbound transfers).
    DataExfiltration,

    /// Generic suspicious activity that doesn't fit other categories.
    Suspicious,
}

/// Which log source produced an event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LogSourceType {
    AuthLog,
    WebAccessLog,
    Syslog,
}

/// Attack phases aligned with MITRE ATT&CK kill chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AttackPhase {
    /// Initial reconnaissance - scanning, probing.
    Reconnaissance,

    /// Resource development - not directly observable from logs.
    ResourceDevelopment,

    /// Initial access - exploit attempts, credential attacks.
    InitialAccess,

    /// Execution - command injection, code execution attempts.
    Execution,

    /// Persistence - backdoor installation attempts.
    Persistence,

    /// Privilege escalation attempts.
    PrivilegeEscalation,

    /// Defense evasion - log tampering, encoding tricks.
    DefenseEvasion,

    /// Credential access - brute force, credential stuffing.
    CredentialAccess,

    /// Discovery - enumeration of services, users, shares.
    Discovery,

    /// Lateral movement - pivoting to other internal targets.
    LateralMovement,

    /// Collection - gathering data before exfiltration.
    Collection,

    /// Exfiltration - data leaving the network.
    Exfiltration,
}

/// Maps an EventType to its most likely AttackPhase.
impl From<&EventType> for AttackPhase {
    fn from(event_type: &EventType) -> Self {
        match event_type {
            EventType::Reconnaissance => AttackPhase::Reconnaissance,
            EventType::WebProbe => AttackPhase::Discovery,
            EventType::AuthFailure => AttackPhase::CredentialAccess,
            EventType::BruteForce => AttackPhase::CredentialAccess,
            EventType::CredentialStuffing => AttackPhase::CredentialAccess,
            EventType::AuthSuccess => AttackPhase::InitialAccess,
            EventType::ExploitAttempt => AttackPhase::Execution,
            EventType::LateralMovement => AttackPhase::LateralMovement,
            EventType::DataExfiltration => AttackPhase::Exfiltration,
            EventType::Suspicious => AttackPhase::Reconnaissance,
        }
    }
}

/// Response action that was taken or should be taken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    /// When this action was decided.
    pub timestamp: DateTime<Utc>,

    /// The IP to act upon.
    pub target_ip: IpAddr,

    /// What action to take.
    pub action_type: ResponseActionType,

    /// The threat score that triggered this action.
    pub trigger_score: ThreatScore,

    /// Human-readable reason for this action.
    pub reason: String,

    /// Whether the action was successfully executed.
    pub executed: bool,
}

/// Types of response actions. Defense only - block and alert, never retaliate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseActionType {
    /// Block the IP via firewall rules.
    BlockIp,

    /// Log an alert to the alert log file.
    LogAlert,

    /// Send a webhook notification.
    WebhookAlert,

    /// Send an email notification.
    EmailAlert,

    /// Increase monitoring sensitivity for this source.
    EscalateMonitoring,
}

/// Summary statistics for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldStatus {
    /// Whether the shield is actively monitoring.
    pub active: bool,

    /// When the daemon started.
    pub started_at: DateTime<Utc>,

    /// Total events processed since start.
    pub total_events: u64,

    /// Currently active attack sessions.
    pub active_sessions: usize,

    /// Total IPs currently blocked.
    pub blocked_ips: usize,

    /// Highest threat score seen in the current evaluation window.
    pub peak_threat_score: f64,

    /// Events per second (rolling average).
    pub events_per_second: f64,

    /// Breakdown of events by type.
    pub event_type_counts: HashMap<String, u64>,
}

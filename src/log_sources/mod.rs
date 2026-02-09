//! Log source abstraction layer for SENTINEL Shield.
//!
//! Copyright (c) 2026 CIPS Corps. All rights reserved.

pub mod auth_log;
pub mod syslog;
pub mod web_log;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::{DetectionEvent, LogSourceType, LogSourcesConfig};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    AuthAttempt,
    AuthFailure,
    AuthSuccess,
    PortProbe,
    WebRequest,
    WebError,
    ServiceDiscovery,
    BruteForce,
    DirectoryTraversal,
    SqlInjection,
    CommandInjection,
    FileAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: DateTime<Utc>,
    pub source_ip: IpAddr,
    pub event_type: EventType,
    pub target_port: Option<u16>,
    pub target_path: Option<String>,
    pub target_service: Option<String>,
    pub success: bool,
    pub raw_line: String,
    pub metadata: HashMap<String, String>,
}

pub trait LogSource: Send + Sync {
    fn name(&self) -> &str;
    fn parse_line(&self, line: &str) -> Option<LogEvent>;
    fn watch_path(&self) -> &Path;
}

/// Tracks byte offsets for each watched log file so we only read new lines
/// on each poll. Handles file rotation (file shrinks) by resetting offset.
struct FileWatcher {
    /// Maps file path to the byte offset of our last read position.
    offsets: HashMap<PathBuf, u64>,
}

impl FileWatcher {
    fn new() -> Self {
        Self {
            offsets: HashMap::new(),
        }
    }

    /// Read new lines from a file since our last read position.
    ///
    /// Returns the new lines as a Vec<String>. Updates the stored offset.
    /// Handles:
    /// - Missing files: logs a warning and returns empty vec.
    /// - File rotation (file shrinks): resets offset to 0 and reads from start.
    /// - Normal growth: reads from last offset to current end.
    fn read_new_lines(&mut self, path: &Path) -> Vec<String> {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("Cannot stat log file {}: {}", path.display(), e);
                return Vec::new();
            }
        };

        let file_size = metadata.len();
        let last_offset = self.offsets.get(path).copied().unwrap_or(0);

        // Detect file rotation: if the file is smaller than our offset,
        // the file was rotated. Reset to beginning.
        let read_from = if file_size < last_offset {
            log::info!(
                "File rotation detected for {} (size {} < offset {}), resetting",
                path.display(),
                file_size,
                last_offset,
            );
            0
        } else if file_size == last_offset {
            // No new data
            return Vec::new();
        } else {
            last_offset
        };

        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("Cannot open log file {}: {}", path.display(), e);
                return Vec::new();
            }
        };

        let mut reader = BufReader::new(file);
        if let Err(e) = reader.seek(SeekFrom::Start(read_from)) {
            log::warn!("Cannot seek in {}: {}", path.display(), e);
            return Vec::new();
        }

        let mut lines = Vec::new();
        let mut current_offset = read_from;

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(bytes_read) => {
                    current_offset += bytes_read as u64;
                    // Only yield complete lines (ending with newline)
                    let trimmed = line.trim_end_matches(['\n', '\r']);
                    if !trimmed.is_empty() {
                        lines.push(trimmed.to_string());
                    }
                }
                Err(e) => {
                    log::warn!("Read error in {}: {}", path.display(), e);
                    break;
                }
            }
        }

        self.offsets.insert(path.to_path_buf(), current_offset);
        lines
    }

    /// Initialize offset to the current end of file so we only read
    /// new data from this point forward. Call this at startup.
    fn seek_to_end(&mut self, path: &Path) {
        match std::fs::metadata(path) {
            Ok(m) => {
                self.offsets.insert(path.to_path_buf(), m.len());
            }
            Err(_) => {
                // File doesn't exist yet -- start from 0 when it appears
                self.offsets.insert(path.to_path_buf(), 0);
            }
        }
    }
}

pub struct LogSourceRegistry {
    sources: Vec<Box<dyn LogSource>>,
    watcher: FileWatcher,
}

impl LogSourceRegistry {
    pub fn new(config: &LogSourcesConfig) -> Self {
        let mut registry = Self {
            sources: Vec::new(),
            watcher: FileWatcher::new(),
        };
        for path in &config.auth_log_paths {
            registry.register(Box::new(auth_log::AuthLogSource::new(path.clone())));
        }
        for (i, path) in config.web_log_paths.iter().enumerate() {
            let name = if config.web_log_paths.len() == 1 {
                "web-access".to_string()
            } else {
                format!("web-access-{}", i)
            };
            registry.register(Box::new(web_log::WebLogSource::new(path.clone(), &name)));
        }
        for path in &config.syslog_paths {
            registry.register(Box::new(syslog::SyslogSource::new(path.clone())));
        }
        registry
    }

    pub fn empty() -> Self {
        Self {
            sources: Vec::new(),
            watcher: FileWatcher::new(),
        }
    }

    pub fn register(&mut self, source: Box<dyn LogSource>) {
        log::info!("Registered log source: {} -> {:?}", source.name(), source.watch_path());
        self.sources.push(source);
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    pub fn sources(&self) -> &[Box<dyn LogSource>] {
        &self.sources
    }

    pub fn source_for_path(&self, path: &Path) -> Option<&dyn LogSource> {
        self.sources.iter().find(|s| s.watch_path() == path).map(|s| s.as_ref())
    }

    /// Seek all watched files to their current end so that the first poll
    /// only returns lines written after daemon start. Call once at startup.
    pub fn seek_all_to_end(&mut self) {
        for source in &self.sources {
            self.watcher.seek_to_end(source.watch_path());
        }
    }

    /// Poll all registered log sources for new events since the last poll.
    ///
    /// For each source, reads new lines from the watched file, parses them
    /// through the source's parser, and converts successful parses into
    /// DetectionEvents.
    ///
    /// Returns all new events across all sources.
    pub fn poll_new_events(&mut self) -> Vec<DetectionEvent> {
        let mut all_events = Vec::new();

        for source in &self.sources {
            let watch_path = source.watch_path().to_path_buf();
            let source_type = source_name_to_type(source.name());
            let new_lines = self.watcher.read_new_lines(&watch_path);

            for line in new_lines {
                if let Some(log_event) = source.parse_line(&line) {
                    all_events.push(log_event.into_detection_event(source_type.clone()));
                }
            }
        }

        all_events
    }

    pub fn default_linux() -> Self {
        let config = LogSourcesConfig {
            auth_log_paths: vec![PathBuf::from("/var/log/auth.log")],
            web_log_paths: vec![PathBuf::from("/var/log/nginx/access.log")],
            syslog_paths: vec![PathBuf::from("/var/log/syslog")],
        };
        Self::new(&config)
    }
}

/// Map a LogSource name to a LogSourceType for DetectionEvent construction.
fn source_name_to_type(name: &str) -> LogSourceType {
    if name.contains("auth") {
        LogSourceType::AuthLog
    } else if name.contains("web") || name.contains("access") || name.contains("nginx") || name.contains("apache") {
        LogSourceType::WebAccessLog
    } else {
        LogSourceType::Syslog
    }
}

impl Default for LogSourceRegistry {
    fn default() -> Self { Self::empty() }
}

impl LogEvent {
    pub fn into_detection_event(self, source_type: LogSourceType) -> DetectionEvent {
        let detection_event_type = match self.event_type {
            EventType::AuthAttempt => crate::EventType::AuthFailure,
            EventType::AuthFailure => crate::EventType::AuthFailure,
            EventType::AuthSuccess => crate::EventType::AuthSuccess,
            EventType::BruteForce => crate::EventType::BruteForce,
            EventType::PortProbe => crate::EventType::Reconnaissance,
            EventType::ServiceDiscovery => crate::EventType::Reconnaissance,
            EventType::WebRequest => crate::EventType::WebProbe,
            EventType::WebError => crate::EventType::WebProbe,
            EventType::DirectoryTraversal => crate::EventType::ExploitAttempt,
            EventType::SqlInjection => crate::EventType::ExploitAttempt,
            EventType::CommandInjection => crate::EventType::ExploitAttempt,
            EventType::FileAccess => crate::EventType::WebProbe,
        };
        DetectionEvent {
            timestamp: self.timestamp,
            source_ip: self.source_ip,
            target_port: self.target_port,
            target_endpoint: self.target_path,
            event_type: detection_event_type,
            source: source_type,
            raw_line: self.raw_line,
        }
    }
}

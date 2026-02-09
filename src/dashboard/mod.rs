//! # Dashboard HTTP Server
//!
//! A lightweight HTTP dashboard for monitoring SENTINEL Shield status.
//! Uses tiny-http for minimal dependency footprint.
//!
//! ## Endpoints
//! - `GET /`          - HTML dashboard overview
//! - `GET /status`    - JSON status summary
//! - `GET /sessions`  - JSON list of active attack sessions
//! - `GET /graph`     - JSON graph state (edges, stats)
//! - `GET /alerts`    - JSON recent alerts
//! - `GET /health`    - Simple health check (200 OK)
//!
//! The dashboard is read-only. It cannot modify shield behavior.
//! All configuration changes must go through the config file.

use crate::{DashboardConfig, ShieldResult};

/// Lightweight HTTP dashboard server for real-time monitoring.
///
/// Binds to the configured address:port and serves status information
/// as both HTML (for humans) and JSON (for monitoring tools).
pub struct DashboardServer {
    config: DashboardConfig,
}

impl DashboardServer {
    /// Create a new dashboard server with the given configuration.
    pub fn new(config: &DashboardConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Start the dashboard server (blocking).
    ///
    /// This should be spawned in a background thread or tokio task.
    pub fn run(&self) -> ShieldResult<()> {
        // TODO: Implementation steps:
        //
        // 1. Bind tiny_http::Server to config.bind_address:config.port
        //
        //    let server = tiny_http::Server::http(
        //        format!("{}:{}", self.config.bind_address, self.config.port)
        //    ).map_err(|e| ShieldError::Dashboard(e.to_string()))?;
        //
        // 2. Accept requests in a loop:
        //
        //    for request in server.incoming_requests() {
        //        match request.url() {
        //            "/" => serve_html_dashboard(&request),
        //            "/status" => serve_json_status(&request),
        //            "/sessions" => serve_json_sessions(&request),
        //            "/graph" => serve_json_graph(&request),
        //            "/alerts" => serve_json_alerts(&request),
        //            "/health" => serve_health(&request),
        //            _ => serve_404(&request),
        //        }
        //    }
        //
        // 3. Each handler reads from shared state (Arc<Mutex<ShieldStatus>>)
        //    and formats the response. The detection engine updates this
        //    shared state on each evaluation cycle.
        //
        // 4. The HTML dashboard should be a single self-contained page
        //    with inline CSS and JS. Auto-refresh every 5 seconds.
        //    Show:
        //    - Shield status (active/inactive)
        //    - Events per second
        //    - Active sessions count
        //    - Blocked IPs count
        //    - Top 10 threat sessions (IP, score, phase)
        //    - Recent alerts
        //    - Graph edge heatmap (10x10 grid)

        log::info!(
            "[DASHBOARD] Server would start on http://{}:{}",
            self.config.bind_address,
            self.config.port,
        );

        Ok(())
    }

    /// Get the bind address string for this dashboard.
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.config.bind_address, self.config.port)
    }
}

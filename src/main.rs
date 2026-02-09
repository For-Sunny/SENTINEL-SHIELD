//! # SENTINEL Shield - CLI Entry Point
//!
//! Command-line interface for the SENTINEL Shield daemon.
//!
//! Commands:
//! - `start`       - Start the detection daemon
//! - `status`      - Show current shield status
//! - `stop`        - Stop the running daemon
//! - `init-config` - Generate a default configuration file

use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sentinel_shield::{ShieldConfig, ShieldError, ShieldResult};
use sentinel_shield::detection::DetectionEngine;
use sentinel_shield::detection::scorer;
use sentinel_shield::log_sources::LogSourceRegistry;
use sentinel_shield::response::ResponseOrchestrator;
use sentinel_shield::graph::AttackGraph;
use sentinel_shield::dashboard::DashboardServer;

/// SENTINEL Shield - Defense-only AI attack detection daemon.
///
/// Watches network logs, detects AI-orchestrated attack patterns,
/// blocks malicious sources, and learns over time. Defense only.
#[derive(Parser, Debug)]
#[command(name = "sentinel-shield")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to configuration file.
    #[arg(short, long, default_value = "sentinel-shield.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the SENTINEL Shield daemon.
    Start,

    /// Show current shield status.
    Status,

    /// Stop the running daemon.
    Stop,

    /// Generate a default configuration file.
    InitConfig,
}

#[tokio::main]
async fn main() -> ShieldResult<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Start => cmd_start(&cli.config).await,
        Commands::Status => cmd_status(&cli.config).await,
        Commands::Stop => cmd_stop(&cli.config).await,
        Commands::InitConfig => cmd_init_config(&cli.config),
    }
}

/// Start the SENTINEL Shield daemon.
///
/// This is the main event loop:
/// 1. Load configuration
/// 2. Initialize log source parsers
/// 3. Initialize detection engine
/// 4. Initialize response orchestrator
/// 5. Initialize attack graph (load from disk if available)
/// 6. Optionally start dashboard
/// 7. Write PID file
/// 8. Install shutdown signal handler
/// 9. Enter the watch-detect-respond loop
async fn cmd_start(config_path: &Path) -> ShieldResult<()> {
    info!("SENTINEL Shield starting...");

    // Load configuration
    let config = if config_path.exists() {
        info!("Loading configuration from: {}", config_path.display());
        ShieldConfig::from_file(config_path)?
    } else {
        info!("No config file found, using defaults. Run 'init-config' to generate one.");
        ShieldConfig::default()
    };

    // Ensure data directory exists
    std::fs::create_dir_all(&config.general.data_dir)?;

    // Write PID file
    let pid_path = config.general.data_dir.join("sentinel-shield.pid");
    write_pid_file(&pid_path)?;
    info!("PID file written to: {}", pid_path.display());

    // Set up graceful shutdown signal
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::SeqCst);
    }) {
        warn!("Could not install signal handler: {}. Use kill to stop.", e);
    }

    // Initialize log source registry and seek to current end of all files
    // so we only process new lines written after daemon start.
    let mut log_registry = LogSourceRegistry::new(&config.log_sources);
    log_registry.seek_all_to_end();
    info!("Log sources registered: {}", log_registry.source_count());

    // Load attack graph from disk if a prior state exists, else create new.
    let graph = if config.general.graph_state_file.exists() {
        match AttackGraph::load(&config.general.graph_state_file) {
            Ok(g) => {
                info!(
                    "Loaded attack graph from disk ({} observations, {} sources)",
                    g.total_observations,
                    g.sources.len(),
                );
                g
            }
            Err(e) => {
                warn!("Failed to load graph state ({}), starting fresh", e);
                AttackGraph::new()
            }
        }
    } else {
        AttackGraph::new()
    };
    info!("Attack graph initialized with {} pattern nodes", graph.node_count());

    let mut response = ResponseOrchestrator::new(&config.response);
    info!("Response orchestrator ready (blocking={})", config.response.blocking_enabled);

    let mut engine = DetectionEngine::new(&config.detection, graph);
    info!("Detection engine online");

    // Start dashboard if enabled
    if config.dashboard.enabled {
        let dashboard = DashboardServer::new(&config.dashboard);
        info!(
            "Dashboard available at http://{}:{}",
            config.dashboard.bind_address, config.dashboard.port
        );
        // TODO: Spawn dashboard in background tokio task when dashboard.run()
        // is fully implemented. For now, suppress warning.
        let _ = dashboard;
    }

    info!("SENTINEL Shield is watching. Defense only. Block and learn.");

    let poll_interval = std::time::Duration::from_secs(config.general.eval_interval_secs);
    let mut total_events: u64 = 0;
    let mut cycles: u64 = 0;
    // Maintenance every 60 cycles (or roughly every 10 minutes at default 10s interval)
    let maintenance_interval: u64 = 60;
    // Session expiry: 1 hour of inactivity
    let session_max_age_secs: i64 = 3600;

    // -----------------------------------------------------------------------
    // Main event loop: Watch -> Detect -> Respond -> Learn
    // -----------------------------------------------------------------------
    loop {
        // 1. Check for shutdown signal
        if shutdown.load(Ordering::SeqCst) {
            info!("Shutdown signal received. Stopping gracefully...");
            break;
        }

        // 2. Poll log sources for new events
        let events = log_registry.poll_new_events();
        let event_count = events.len();

        if event_count > 0 {
            total_events += event_count as u64;
            info!("Polled {} new events (total: {})", event_count, total_events);
        }

        // 3. Feed events into detection engine
        if !events.is_empty() {
            match engine.process_events(events) {
                Ok(threatening_sessions) => {
                    // 4. For each threatening session, trigger response
                    for session in &threatening_sessions {
                        // Skip sessions that have already been responded to
                        if session.response_taken {
                            continue;
                        }

                        let reason = format!(
                            "Threat detected: {} events, {} ports, {} endpoints, phases: {:?}",
                            session.event_count(),
                            session.targeted_ports.len(),
                            session.targeted_endpoints.len(),
                            session.attack_phases,
                        );

                        info!(
                            "THREAT: {} - {} (session {})",
                            session.source_ip,
                            scorer::format_score(&session.threat_score),
                            session.id,
                        );

                        match response.respond(
                            session.source_ip,
                            session.threat_score,
                            &reason,
                        ) {
                            Ok(actions) => {
                                for action in &actions {
                                    info!(
                                        "  Action: {:?} against {} (executed: {})",
                                        action.action_type, action.target_ip, action.executed,
                                    );
                                }
                            }
                            Err(e) => {
                                error!("Response failed for {}: {}", session.source_ip, e);
                            }
                        }
                    }

                    // Mark responded sessions so we don't re-trigger
                    // (engine owns the sessions, we update through it)
                    let threshold = config.detection.threat_threshold;
                    for session in engine.sessions_mut().values_mut() {
                        if session.threat_score.is_threat(threshold) && !session.response_taken {
                            session.response_taken = true;
                        }
                    }
                }
                Err(e) => {
                    error!("Detection engine error: {}", e);
                }
            }

            // 5. Update graph with learned patterns
            engine.update_graph();
        }

        cycles += 1;

        // 6. Periodic maintenance
        if cycles.is_multiple_of(maintenance_interval) {
            // Prune old sessions
            let before = engine.sessions().len();
            engine.prune_sessions(session_max_age_secs);
            let pruned = before - engine.sessions().len();
            if pruned > 0 {
                info!("Pruned {} stale sessions", pruned);
            }

            // Decay and prune the attack graph
            engine.graph_mut().learn();
            engine.graph_mut().prune(chrono::Utc::now());

            // Save graph state to disk
            if let Err(e) = engine.graph().save(&config.general.graph_state_file) {
                error!("Failed to save graph state: {}", e);
            } else {
                let stats = engine.graph().stats();
                info!(
                    "Graph saved ({} observations, {} active sources, {} edges)",
                    stats.total_observations, stats.active_sources, stats.active_edges,
                );
            }
        }

        // 7. Sleep for poll interval
        std::thread::sleep(poll_interval);
    }

    // -----------------------------------------------------------------------
    // Graceful shutdown: save state and clean up
    // -----------------------------------------------------------------------
    info!("Saving final graph state...");
    if let Err(e) = engine.graph().save(&config.general.graph_state_file) {
        error!("Failed to save graph state on shutdown: {}", e);
    }

    // Remove PID file
    if let Err(e) = std::fs::remove_file(&pid_path) {
        warn!("Could not remove PID file: {}", e);
    }

    info!(
        "SENTINEL Shield stopped. Processed {} total events across {} cycles.",
        total_events, cycles,
    );

    Ok(())
}

/// Show the current status of the running daemon.
async fn cmd_status(config_path: &Path) -> ShieldResult<()> {
    let config = if config_path.exists() {
        ShieldConfig::from_file(config_path)?
    } else {
        ShieldConfig::default()
    };

    let pid_path = config.general.data_dir.join("sentinel-shield.pid");

    // Check if daemon is running via PID file
    match read_pid_file(&pid_path) {
        Some(pid) => {
            if is_process_running(pid) {
                println!("SENTINEL Shield is RUNNING (PID: {})", pid);
            } else {
                println!("SENTINEL Shield is NOT RUNNING (stale PID file, PID {} not found)", pid);
                println!("  The daemon may have crashed. Remove {} to clear.", pid_path.display());
            }
        }
        None => {
            println!("SENTINEL Shield is NOT RUNNING (no PID file)");
        }
    }

    // Report on data directory and graph state
    if config.general.data_dir.exists() {
        println!("Data directory: {}", config.general.data_dir.display());

        if config.general.graph_state_file.exists() {
            let metadata = std::fs::metadata(&config.general.graph_state_file)?;
            println!("Graph state: {} ({} bytes)", config.general.graph_state_file.display(), metadata.len());

            // Try to load and report graph stats
            match AttackGraph::load(&config.general.graph_state_file) {
                Ok(graph) => {
                    let stats = graph.stats();
                    println!("  Observations: {}", stats.total_observations);
                    println!("  Active sources: {}", stats.active_sources);
                    println!("  Active edges: {}/{}", stats.active_edges, stats.total_possible_edges);
                    println!("  Edge density: {:.1}%", stats.edge_density * 100.0);
                    println!("  Learn cycles: {}", stats.learn_cycles);
                    println!("  Chains detected: {}", stats.total_chains_detected);
                }
                Err(e) => {
                    println!("  (Could not load graph for stats: {})", e);
                }
            }
        } else {
            println!("Graph state: not found (daemon may not have run yet)");
        }

        // Report alert log
        if config.response.alert_log_path.exists() {
            let metadata = std::fs::metadata(&config.response.alert_log_path)?;
            println!("Alert log: {} ({} bytes)", config.response.alert_log_path.display(), metadata.len());
        }
    } else {
        println!("No data directory found. Run 'sentinel-shield start' first.");
    }

    // Report config
    println!();
    println!("Configuration:");
    println!("  Poll interval: {}s", config.general.eval_interval_secs);
    println!("  Threat threshold: {}", config.detection.threat_threshold);
    println!("  Blocking enabled: {}", config.response.blocking_enabled);
    println!("  Dashboard enabled: {}", config.dashboard.enabled);
    if config.dashboard.enabled {
        println!("  Dashboard: http://{}:{}", config.dashboard.bind_address, config.dashboard.port);
    }
    println!("  Log sources: {} auth, {} web, {} syslog",
        config.log_sources.auth_log_paths.len(),
        config.log_sources.web_log_paths.len(),
        config.log_sources.syslog_paths.len(),
    );

    Ok(())
}

/// Stop the running daemon.
async fn cmd_stop(config_path: &Path) -> ShieldResult<()> {
    let config = if config_path.exists() {
        ShieldConfig::from_file(config_path)?
    } else {
        ShieldConfig::default()
    };

    let pid_path = config.general.data_dir.join("sentinel-shield.pid");

    match read_pid_file(&pid_path) {
        Some(pid) => {
            if !is_process_running(pid) {
                println!("Process {} is not running (stale PID file). Cleaning up.", pid);
                let _ = std::fs::remove_file(&pid_path);
                return Ok(());
            }

            println!("Sending stop signal to SENTINEL Shield (PID: {})...", pid);

            #[cfg(unix)]
            {
                use std::process::Command;
                let status = Command::new("kill")
                    .args(["-TERM", &pid.to_string()])
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        println!("Stop signal sent. Daemon should shut down gracefully.");
                    }
                    Ok(s) => {
                        println!("Kill command exited with: {}. You may need to stop it manually.", s);
                    }
                    Err(e) => {
                        println!("Failed to send signal: {}. Try: kill {} manually.", e, pid);
                    }
                }
            }

            #[cfg(windows)]
            {
                use std::process::Command;
                // On Windows, use taskkill to send a termination signal.
                // The ctrlc handler in the daemon will catch this.
                let status = Command::new("taskkill")
                    .args(["/PID", &pid.to_string()])
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        println!("Stop signal sent. Daemon should shut down gracefully.");
                    }
                    Ok(s) => {
                        println!("taskkill exited with: {}. You may need to stop it manually.", s);
                    }
                    Err(e) => {
                        println!("Failed to send signal: {}. Try: taskkill /PID {} manually.", e, pid);
                    }
                }
            }
        }
        None => {
            println!("No PID file found at {}. Is the daemon running?", pid_path.display());
            println!("If the daemon is running, find its PID with 'ps' or 'tasklist' and kill it manually.");
        }
    }

    Ok(())
}

/// Generate a default configuration file.
fn cmd_init_config(config_path: &Path) -> ShieldResult<()> {
    if config_path.exists() {
        return Err(ShieldError::Config(format!(
            "Configuration file already exists: {}. Remove it first or use a different path.",
            config_path.display()
        )));
    }

    ShieldConfig::write_default(config_path)?;
    println!("Default configuration written to: {}", config_path.display());
    println!("Edit this file to configure log sources, detection thresholds, and response actions.");
    println!();
    println!("Key settings to configure:");
    println!("  [log_sources] - Point to your actual log files");
    println!("  [detection]   - Tune threat_threshold (default 0.7)");
    println!("  [response]    - Enable blocking_enabled when ready (default false / dry-run)");
    println!("  [dashboard]   - Dashboard runs on http://127.0.0.1:8080 by default");

    Ok(())
}

// ---------------------------------------------------------------------------
// PID file management
// ---------------------------------------------------------------------------

/// Write the current process PID to a file.
fn write_pid_file(path: &Path) -> ShieldResult<()> {
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())?;
    Ok(())
}

/// Read a PID from a PID file. Returns None if file doesn't exist or is invalid.
fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// Check if a process with the given PID is still running.
fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // On Unix, kill(pid, 0) checks if process exists without sending a signal.
        use std::process::Command;
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        // On Windows, use tasklist to check if the PID exists.
        let output = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH"])
            .output();
        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // tasklist returns "INFO: No tasks are running..." when PID not found
                !stdout.contains("No tasks") && stdout.contains(&pid.to_string())
            }
            Err(_) => false,
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

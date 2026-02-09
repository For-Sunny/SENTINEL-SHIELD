//! # Response Action Orchestrator
//!
//! Executes defensive actions when the detection engine identifies threats.
//! DEFENSE ONLY - the response module can block and alert, never retaliate.
//!
//! Actions include:
//! - IP blocking via system firewall (iptables on Linux, netsh on Windows)
//! - Alert logging to a dedicated alert log file
//! - Webhook notifications for real-time alerting
//! - Email notifications for critical threats
//!
//! All actions are logged for forensic review. The module supports a dry-run
//! mode where actions are logged but not executed.

pub mod blocker;
pub mod alerter;

use crate::{ResponseAction, ResponseActionType, ResponseConfig, ShieldResult, ThreatScore};
use std::net::IpAddr;
use chrono::Utc;

/// Orchestrates response actions when threats are detected.
///
/// The orchestrator decides which actions to take based on the threat
/// score and configuration, then delegates to the blocker and alerter.
pub struct ResponseOrchestrator {
    config: ResponseConfig,
    /// History of actions taken (for deduplication and audit).
    action_history: Vec<ResponseAction>,
}

impl ResponseOrchestrator {
    /// Create a new response orchestrator with the given configuration.
    pub fn new(config: &ResponseConfig) -> Self {
        Self {
            config: config.clone(),
            action_history: Vec::new(),
        }
    }

    /// Execute appropriate response actions for a detected threat.
    ///
    /// # Arguments
    /// * `source_ip` - The IP address to act upon.
    /// * `score` - The threat score that triggered this response.
    /// * `reason` - Human-readable description of why this action is being taken.
    ///
    /// # Returns
    /// A list of actions that were attempted, with their execution status.
    pub fn respond(
        &mut self,
        source_ip: IpAddr,
        score: ThreatScore,
        reason: &str,
    ) -> ShieldResult<Vec<ResponseAction>> {
        let mut actions = Vec::new();

        // Always log an alert
        let alert_action = ResponseAction {
            timestamp: Utc::now(),
            target_ip: source_ip,
            action_type: ResponseActionType::LogAlert,
            trigger_score: score,
            reason: reason.to_string(),
            executed: false,
        };
        actions.push(alert_action);

        // Block IP if blocking is enabled and score is above threshold
        if self.config.blocking_enabled {
            let block_action = ResponseAction {
                timestamp: Utc::now(),
                target_ip: source_ip,
                action_type: ResponseActionType::BlockIp,
                trigger_score: score,
                reason: reason.to_string(),
                executed: false,
            };
            actions.push(block_action);
        }

        // Webhook notification if configured
        if self.config.webhook_url.is_some() {
            let webhook_action = ResponseAction {
                timestamp: Utc::now(),
                target_ip: source_ip,
                action_type: ResponseActionType::WebhookAlert,
                trigger_score: score,
                reason: reason.to_string(),
                executed: false,
            };
            actions.push(webhook_action);
        }

        // Email notification if configured
        if self.config.alert_email.is_some() {
            let email_action = ResponseAction {
                timestamp: Utc::now(),
                target_ip: source_ip,
                action_type: ResponseActionType::EmailAlert,
                trigger_score: score,
                reason: reason.to_string(),
                executed: false,
            };
            actions.push(email_action);
        }

        // Execute each action via the appropriate subsystem.
        // Never let a response failure crash the daemon.
        for action in &mut actions {
            match action.action_type {
                ResponseActionType::LogAlert => {
                    match alerter::log_alert(
                        &self.config.alert_log_path,
                        &action.target_ip,
                        &action.trigger_score,
                        &action.reason,
                    ) {
                        Ok(()) => {
                            action.executed = true;
                        }
                        Err(e) => {
                            log::error!(
                                "[RESPONSE] Failed to log alert for {}: {}",
                                action.target_ip, e
                            );
                        }
                    }
                }
                ResponseActionType::BlockIp => {
                    // Skip if already blocked (deduplication)
                    if self.is_blocked(&action.target_ip) {
                        log::info!(
                            "[RESPONSE] IP {} already blocked, skipping duplicate",
                            action.target_ip
                        );
                        action.executed = true;
                    } else {
                        match blocker::block_ip(&action.target_ip) {
                            Ok(()) => {
                                action.executed = true;
                            }
                            Err(e) => {
                                log::error!(
                                    "[RESPONSE] Failed to block IP {}: {}",
                                    action.target_ip, e
                                );
                            }
                        }
                    }
                }
                ResponseActionType::WebhookAlert => {
                    if let Some(ref url) = self.config.webhook_url {
                        match alerter::send_webhook(
                            url,
                            &action.target_ip,
                            &action.trigger_score,
                            &action.reason,
                        ) {
                            Ok(()) => {
                                action.executed = true;
                            }
                            Err(e) => {
                                log::error!(
                                    "[RESPONSE] Failed to send webhook for {}: {}",
                                    action.target_ip, e
                                );
                            }
                        }
                    }
                }
                ResponseActionType::EmailAlert => {
                    if let Some(ref email) = self.config.alert_email {
                        // Use the alert_log_path's parent as the alert_dir for email queue
                        let alert_dir = self.config.alert_log_path
                            .parent()
                            .unwrap_or_else(|| std::path::Path::new("."));
                        match alerter::send_email(
                            email,
                            &action.target_ip,
                            &action.trigger_score,
                            &action.reason,
                            alert_dir,
                        ) {
                            Ok(()) => {
                                action.executed = true;
                            }
                            Err(e) => {
                                log::error!(
                                    "[RESPONSE] Failed to queue email for {}: {}",
                                    action.target_ip, e
                                );
                            }
                        }
                    }
                }
                ResponseActionType::EscalateMonitoring => {
                    // Not yet implemented - log for future expansion
                    log::info!(
                        "[RESPONSE] EscalateMonitoring for {} (not yet implemented)",
                        action.target_ip
                    );
                }
            }
        }

        // Record all actions in history
        self.action_history.extend(actions.clone());

        Ok(actions)
    }

    /// Check if an IP has already been blocked (deduplication).
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.action_history.iter().any(|a| {
            a.target_ip == *ip
                && a.action_type == ResponseActionType::BlockIp
                && a.executed
        })
    }

    /// Get the full action history for audit purposes.
    pub fn action_history(&self) -> &[ResponseAction] {
        &self.action_history
    }

    /// Number of IPs currently blocked.
    pub fn blocked_count(&self) -> usize {
        self.action_history
            .iter()
            .filter(|a| a.action_type == ResponseActionType::BlockIp && a.executed)
            .map(|a| a.target_ip)
            .collect::<std::collections::HashSet<_>>()
            .len()
    }
}

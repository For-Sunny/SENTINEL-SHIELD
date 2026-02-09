//! # IP Blocker
//!
//! Blocks malicious IP addresses via the system firewall.
//! DEFENSE ONLY - block and log, never retaliate.
//!
//! ## Platform Support
//! - **Linux**: iptables rules with comment tagging
//! - **Windows**: netsh advfirewall rules with SENTINEL prefix
//!
//! The blocker creates rules with a SENTINEL-SHIELD prefix/tag so they
//! can be identified and managed without interfering with existing rules.
//!
//! ## Safety
//! - Never blocks private/loopback addresses (127.0.0.1, 10.x, 172.16-31.x, 192.168.x)
//! - All IPs validated via std::net::IpAddr before shell execution (no injection)
//! - Supports automatic expiry (block duration from config)
//! - All block/unblock actions are logged

use std::net::IpAddr;
use std::process::Command;
use crate::ShieldResult;

/// The rule tag/comment used to identify SENTINEL Shield firewall rules.
const RULE_TAG: &str = "SENTINEL-SHIELD-BLOCK";

/// Check if an IP address is in a private/reserved range.
///
/// We never block private addresses to prevent accidental lockout of
/// internal services or the administrator's own connection.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()             // 127.0.0.0/8
                || v4.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()     // 169.254.0.0/16
                || v4.is_broadcast()      // 255.255.255.255
                || v4.is_unspecified()    // 0.0.0.0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
        }
    }
}

/// Validate and canonicalize an IP string.
///
/// The IP has already been parsed into `std::net::IpAddr` by the time it reaches
/// the blocker, so command injection is structurally impossible. This function
/// uses `IpAddr::to_string()` which only produces valid IP notation -- never
/// shell metacharacters.
fn safe_ip_string(ip: &IpAddr) -> String {
    // IpAddr::to_string() is guaranteed to produce a valid IP representation.
    // No semicolons, pipes, backticks, or other shell metacharacters possible.
    ip.to_string()
}

/// Build the firewall rule name for a given IP.
fn rule_name(ip: &IpAddr) -> String {
    format!("{}-{}", RULE_TAG, safe_ip_string(ip))
}

/// Block an IP address via the system firewall.
///
/// # Arguments
/// * `ip` - The IP address to block. Must be a public address.
///
/// # Returns
/// Ok(()) if the block was applied successfully.
/// Err if the IP is private or the firewall command failed.
///
/// # Safety
/// This function executes system commands (iptables/netsh).
/// The IP is validated through Rust's `std::net::IpAddr` type system,
/// preventing command injection. It should only be called when
/// `config.blocking_enabled` is true.
pub fn block_ip(ip: &IpAddr) -> ShieldResult<()> {
    if is_private_ip(ip) {
        return Err(crate::ShieldError::Response(format!(
            "Refusing to block private/reserved IP: {}",
            ip
        )));
    }

    let ip_str = safe_ip_string(ip);

    if cfg!(target_os = "linux") {
        let output = Command::new("iptables")
            .args([
                "-A", "INPUT",
                "-s", &ip_str,
                "-j", "DROP",
                "-m", "comment", "--comment", RULE_TAG,
            ])
            .output()
            .map_err(|e| crate::ShieldError::Response(format!(
                "Failed to execute iptables: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::ShieldError::Response(format!(
                "iptables block failed for {}: {}", ip_str, stderr
            )));
        }

        log::info!("[BLOCK] Blocked IP via iptables: {} (tag: {})", ip_str, RULE_TAG);
    } else if cfg!(target_os = "windows") {
        let name = rule_name(ip);
        let output = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", name),
                "dir=in",
                "action=block",
                &format!("remoteip={}", ip_str),
            ])
            .output()
            .map_err(|e| crate::ShieldError::Response(format!(
                "Failed to execute netsh: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::ShieldError::Response(format!(
                "netsh block failed for {}: {}", ip_str, stderr
            )));
        }

        log::info!("[BLOCK] Blocked IP via netsh: {} (rule: {})", ip_str, name);
    } else {
        log::warn!("[BLOCK] Unsupported platform - block not executed for {}", ip_str);
        return Err(crate::ShieldError::Response(
            "IP blocking not supported on this platform".to_string()
        ));
    }

    Ok(())
}

/// Remove a block for a specific IP address.
///
/// # Arguments
/// * `ip` - The IP address to unblock.
pub fn unblock_ip(ip: &IpAddr) -> ShieldResult<()> {
    let ip_str = safe_ip_string(ip);

    if cfg!(target_os = "linux") {
        let output = Command::new("iptables")
            .args([
                "-D", "INPUT",
                "-s", &ip_str,
                "-j", "DROP",
                "-m", "comment", "--comment", RULE_TAG,
            ])
            .output()
            .map_err(|e| crate::ShieldError::Response(format!(
                "Failed to execute iptables: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::ShieldError::Response(format!(
                "iptables unblock failed for {}: {}", ip_str, stderr
            )));
        }

        log::info!("[UNBLOCK] Unblocked IP via iptables: {} (tag: {})", ip_str, RULE_TAG);
    } else if cfg!(target_os = "windows") {
        let name = rule_name(ip);
        let output = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "delete", "rule",
                &format!("name={}", name),
            ])
            .output()
            .map_err(|e| crate::ShieldError::Response(format!(
                "Failed to execute netsh: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::ShieldError::Response(format!(
                "netsh unblock failed for {}: {}", ip_str, stderr
            )));
        }

        log::info!("[UNBLOCK] Unblocked IP via netsh: {} (rule: {})", ip_str, name);
    } else {
        log::warn!("[UNBLOCK] Unsupported platform - unblock not executed for {}", ip_str);
        return Err(crate::ShieldError::Response(
            "IP unblocking not supported on this platform".to_string()
        ));
    }

    Ok(())
}

/// Remove all SENTINEL Shield firewall rules.
///
/// Uses platform-specific commands to find and remove only rules tagged
/// with the SENTINEL-SHIELD-BLOCK identifier.
pub fn clear_all_blocks() -> ShieldResult<()> {
    if cfg!(target_os = "linux") {
        // List all INPUT rules, find SENTINEL-tagged ones, delete in reverse order
        // to avoid index shifting.
        let output = Command::new("iptables")
            .args(["-L", "INPUT", "--line-numbers", "-n"])
            .output()
            .map_err(|e| crate::ShieldError::Response(format!(
                "Failed to list iptables rules: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::ShieldError::Response(format!(
                "iptables list failed: {}", stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Collect line numbers of SENTINEL rules (in reverse to avoid index shift)
        let mut rule_numbers: Vec<u32> = Vec::new();
        for line in stdout.lines() {
            if line.contains(RULE_TAG) {
                // Line format: "NUM  target  prot  opt  source  destination  ..."
                if let Some(num_str) = line.split_whitespace().next() {
                    if let Ok(num) = num_str.parse::<u32>() {
                        rule_numbers.push(num);
                    }
                }
            }
        }

        // Delete in reverse order so line numbers stay valid
        rule_numbers.sort_unstable();
        rule_numbers.reverse();

        for num in &rule_numbers {
            let delete_result = Command::new("iptables")
                .args(["-D", "INPUT", &num.to_string()])
                .output();

            match delete_result {
                Ok(out) if out.status.success() => {
                    log::info!("[CLEAR] Removed iptables rule #{}", num);
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    log::warn!("[CLEAR] Failed to remove iptables rule #{}: {}", num, stderr);
                }
                Err(e) => {
                    log::warn!("[CLEAR] Failed to execute iptables delete for rule #{}: {}", num, e);
                }
            }
        }

        log::info!("[CLEAR] Removed {} SENTINEL Shield iptables rules", rule_numbers.len());
    } else if cfg!(target_os = "windows") {
        // On Windows, list all firewall rules and find SENTINEL-tagged ones.
        let output = Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", "name=all", "dir=in"])
            .output()
            .map_err(|e| crate::ShieldError::Response(format!(
                "Failed to list netsh rules: {}", e
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::ShieldError::Response(format!(
                "netsh list failed: {}", stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut removed = 0u32;

        // Parse rule names that start with SENTINEL-SHIELD-BLOCK
        for line in stdout.lines() {
            let trimmed = line.trim();
            // netsh output: "Rule Name:   SENTINEL-SHIELD-BLOCK-1.2.3.4"
            if let Some(name_part) = trimmed.strip_prefix("Rule Name:") {
                let name = name_part.trim();
                if name.starts_with(RULE_TAG) {
                    let delete_result = Command::new("netsh")
                        .args([
                            "advfirewall", "firewall", "delete", "rule",
                            &format!("name={}", name),
                        ])
                        .output();

                    match delete_result {
                        Ok(out) if out.status.success() => {
                            log::info!("[CLEAR] Removed netsh rule: {}", name);
                            removed += 1;
                        }
                        Ok(out) => {
                            let stderr = String::from_utf8_lossy(&out.stderr);
                            log::warn!("[CLEAR] Failed to remove netsh rule {}: {}", name, stderr);
                        }
                        Err(e) => {
                            log::warn!("[CLEAR] Failed to execute netsh delete for {}: {}", name, e);
                        }
                    }
                }
            }
        }

        log::info!("[CLEAR] Removed {} SENTINEL Shield netsh rules", removed);
    } else {
        log::warn!("[CLEAR] Unsupported platform - cannot clear firewall rules");
        return Err(crate::ShieldError::Response(
            "Clearing firewall rules not supported on this platform".to_string()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));

        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn test_block_private_ip_rejected() {
        let result = block_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(result.is_err());
    }

    #[test]
    fn test_block_public_ip_ok() {
        // On the build platform, this will attempt real firewall commands.
        // The test verifies it doesn't panic; the command may fail without
        // admin privileges, which is acceptable in a test environment.
        let _result = block_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)));
        // We don't assert Ok because the command may fail without admin rights.
        // The important thing is: no panic, no injection, private IPs rejected.
    }

    #[test]
    fn test_safe_ip_string_no_injection() {
        // IpAddr guarantees safe output - verify the canonicalization
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let s = safe_ip_string(&ip);
        assert_eq!(s, "8.8.8.8");
        assert!(!s.contains(';'));
        assert!(!s.contains('|'));
        assert!(!s.contains('`'));
        assert!(!s.contains('$'));

        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
        let s6 = safe_ip_string(&ipv6);
        assert_eq!(s6, "2001:db8::1");
        assert!(!s6.contains(';'));
    }

    #[test]
    fn test_rule_name_format() {
        let ip: IpAddr = "203.0.113.50".parse().unwrap();
        let name = rule_name(&ip);
        assert_eq!(name, "SENTINEL-SHIELD-BLOCK-203.0.113.50");
    }
}

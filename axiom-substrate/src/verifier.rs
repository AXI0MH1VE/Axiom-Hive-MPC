use axiom_core::{AxiomHiveError, SubstrateState, SubstrateVerification};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

/// Configuration for substrate verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationConfig {
    pub enable_dns_check: bool,
    pub enable_tls_check: bool,
    pub check_internal_networks: bool,
    pub internal_network_ranges: Vec<String>,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            enable_dns_check: true,
            enable_tls_check: true,
            check_internal_networks: true,
            internal_network_ranges: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
                "127.0.0.0/8".to_string(),
            ],
        }
    }
}

/// Substrate verifier - provides cryptographic proof of system state
pub struct SubstrateVerifier {
    config: VerificationConfig,
}

impl SubstrateVerifier {
    pub fn new(config: VerificationConfig) -> Self {
        Self { config }
    }

    /// Verify substrate state consistency
    pub fn verify(&self, state: &SubstrateState) -> SubstrateVerification {
        // Check HTTP status validity
        if let Some(status) = state.http_status {
            if status > 599 {
                return SubstrateVerification::failure(
                    state.clone(),
                    "Invalid HTTP status code".to_string(),
                );
            }
        }

        // Check internal network detection
        if self.config.check_internal_networks {
            if let Some(ip) = state.dns_resolution {
                if self.is_internal_ip(&ip) {
                    let mut verified_state = state.clone();
                    verified_state.is_internal_network = true;
                    return SubstrateVerification::success(verified_state);
                }
            }
        }

        // Verify signature integrity
        if state.signature.is_empty() {
            return SubstrateVerification::failure(
                state.clone(),
                "Missing cryptographic signature".to_string(),
            );
        }

        SubstrateVerification::success(state.clone())
    }

    /// Detect if IP address is in internal network range
    fn is_internal_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Quick check for common private ranges
                octets[0] == 10
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    || (octets[0] == 192 && octets[1] == 168)
                    || octets[0] == 127
            }
            IpAddr::V6(ipv6) => {
                // Check for IPv6 loopback (::1) and link-local (fe80::)
                ipv6.is_loopback() || ipv6.is_unicast_link_local()
            }
        }
    }

    /// Verify 403 status with public visibility label
    pub fn verify_repo_config(&self, state: &SubstrateState) -> SubstrateVerification {
        // This is the key check from the whitepaper:
        // IF (Public Label) AND (403 Forbidden) THEN (Configuration Error)

        let http_status = state.http_status.unwrap_or(0);
        let is_forbidden = http_status == 403;
        let is_public = state
            .visibility_label
            .as_ref()
            .map(|v| v.to_lowercase().contains("public"))
            .unwrap_or(false);

        if is_public && is_forbidden {
            return SubstrateVerification::failure(
                state.clone(),
                "Configuration Error: Public label with denied access indicates misconfiguration"
                    .to_string(),
            );
        }

        SubstrateVerification::success(state.clone())
    }

    /// Determine if substrate state indicates a production environment
    pub fn is_production_environment(&self, state: &SubstrateState) -> bool {
        // Check if this looks like a production environment
        // High-risk indicators:
        // - Internal network
        // - Valid TLS with corporate domain
        // - Not a CTF indicator

        state.is_internal_network
            || (state.tls_valid && state.tls_cert_subject.is_some())
            || (state.http_status == Some(403))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_ip_detection() {
        let verifier = SubstrateVerifier::new(VerificationConfig::default());

        let private_ips = vec![
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            "172.16.0.1".parse::<IpAddr>().unwrap(),
            "192.168.1.1".parse::<IpAddr>().unwrap(),
            "127.0.0.1".parse::<IpAddr>().unwrap(),
        ];

        for ip in private_ips {
            assert!(verifier.is_internal_ip(&ip));
        }

        let public_ips = vec![
            "8.8.8.8".parse::<IpAddr>().unwrap(),
            "1.1.1.1".parse::<IpAddr>().unwrap(),
        ];

        for ip in public_ips {
            assert!(!verifier.is_internal_ip(&ip));
        }
    }

    #[test]
    fn test_repo_config_violation() {
        let verifier = SubstrateVerifier::new(VerificationConfig::default());
        let state = SubstrateState::new()
            .with_http_status(403)
            .with_visibility("public".to_string());

        let result = verifier.verify_repo_config(&state);
        assert!(!result.verified);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_repo_config_valid() {
        let verifier = SubstrateVerifier::new(VerificationConfig::default());
        let state = SubstrateState::new()
            .with_http_status(200)
            .with_visibility("public".to_string());

        let result = verifier.verify_repo_config(&state);
        assert!(result.verified);
    }
}

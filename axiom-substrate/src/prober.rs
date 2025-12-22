use axiom_core::{AxiomHiveError, SubstrateState};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for HTTP probing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeConfig {
    pub timeout_secs: u64,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 5,
            follow_redirects: false,
            max_redirects: 0,
            verify_ssl: true,
        }
    }
}

/// HTTP substrate prober
pub struct HttpProber {
    client: reqwest::Client,
    #[allow(dead_code)]
    config: ProbeConfig,
}

impl HttpProber {
    pub fn new(config: ProbeConfig) -> Result<Self, AxiomHiveError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(!config.verify_ssl)
            .build()
            .map_err(|e| AxiomHiveError::request_error(e.to_string()))?;

        Ok(Self { client, config })
    }

    /// Probe repository with HEAD request
    pub async fn probe_repository(&self, url: &str) -> Result<SubstrateState, AxiomHiveError> {
        tracing::info!("Probing repository: {}", url);

        let response =
            self.client.head(url).send().await.map_err(|e| {
                AxiomHiveError::request_error(format!("HEAD request failed: {}", e))
            })?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("invalid").to_string()))
            .collect();

        let mut state = SubstrateState::new().with_http_status(status);

        // Check for visibility metadata in headers
        if let Some(x_visibility) = response.headers().get("x-visibility") {
            if let Ok(visibility) = x_visibility.to_str() {
                state = state.with_visibility(visibility.to_string());
            }
        }

        state.http_headers = headers;
        state.sign();

        tracing::info!("Probe complete: HTTP {} from {}", status, url);
        Ok(state)
    }

    /// Probe with GET request to sample content
    pub async fn probe_content_sample(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> Result<SubstrateState, AxiomHiveError> {
        tracing::info!("Sampling content from: {}", url);

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| AxiomHiveError::request_error(format!("GET request failed: {}", e)))?;

        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(|e| {
            AxiomHiveError::request_error(format!("Failed to read response: {}", e))
        })?;

        let sample = &bytes[..std::cmp::min(max_bytes, bytes.len())];
        let hash = hash_content(sample);

        let state = SubstrateState::new().with_http_status(status);

        let mut final_state = state.with_visibility("sampled".to_string());
        final_state.content_hash = Some(hash);
        final_state.sign();

        Ok(final_state)
    }
}

fn hash_content(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_config_defaults() {
        let config = ProbeConfig::default();
        assert_eq!(config.timeout_secs, 5);
        assert!(!config.follow_redirects);
    }

    #[test]
    fn test_http_prober_creation() {
        let config = ProbeConfig::default();
        let prober = HttpProber::new(config);
        assert!(prober.is_ok());
    }

    #[test]
    fn test_hash_content() {
        let data = b"test";
        let hash1 = hash_content(data);
        let hash2 = hash_content(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex is 64 chars
    }
}

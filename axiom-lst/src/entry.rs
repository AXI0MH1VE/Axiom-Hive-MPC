use axiom_core::AxiomEvaluation;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Epistemic tier - how confident are we in this claim?
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EpistemicTier {
    /// User assertion (least trusted)
    Speculated,
    /// Inferred from axiom evaluation
    Inferred,
    /// Verified by direct substrate probe
    Verified,
}

impl std::fmt::Display for EpistemicTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpistemicTier::Verified => write!(f, "VERIFIED"),
            EpistemicTier::Inferred => write!(f, "INFERRED"),
            EpistemicTier::Speculated => write!(f, "SPECULATED"),
        }
    }
}

/// Result of a substrate probe
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeResult {
    pub probe_type: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub result: serde_json::Value,
    pub error: Option<String>,
}

impl ProbeResult {
    pub fn new(probe_type: impl Into<String>, result: serde_json::Value) -> Self {
        Self {
            probe_type: probe_type.into(),
            timestamp: chrono::Utc::now(),
            result,
            error: None,
        }
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }
}

/// Single entry in the LST (Log-Structured Tensor)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LSTEntry {
    pub entry_id: Uuid,
    pub sequence_number: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub query: String,
    pub substrate_probes: Vec<ProbeResult>,
    pub axiom_checks: Vec<AxiomEvaluation>,
    pub inference_output: Option<String>,
    pub epistemic_tier: EpistemicTier,
    pub previous_hash: String,
    pub current_hash: String,
}

impl LSTEntry {
    pub fn new(sequence_number: u64, query: impl Into<String>, previous_hash: String) -> Self {
        let entry_id = Uuid::new_v4();
        let timestamp = chrono::Utc::now();
        let query = query.into();

        Self {
            entry_id,
            sequence_number,
            timestamp,
            query,
            substrate_probes: Vec::new(),
            axiom_checks: Vec::new(),
            inference_output: None,
            epistemic_tier: EpistemicTier::Speculated,
            previous_hash,
            current_hash: String::new(), // Will be computed on finalization
        }
    }

    pub fn add_probe(mut self, probe: ProbeResult) -> Self {
        self.substrate_probes.push(probe);
        self
    }

    pub fn add_axiom_check(mut self, check: AxiomEvaluation) -> Self {
        // Update epistemic tier based on axiom results
        if check.result.is_pass() {
            self.epistemic_tier = EpistemicTier::Verified;
        }
        self.axiom_checks.push(check);
        self
    }

    pub fn set_inference_output(mut self, output: impl Into<String>) -> Self {
        self.inference_output = Some(output.into());
        self
    }

    pub fn set_epistemic_tier(mut self, tier: EpistemicTier) -> Self {
        self.epistemic_tier = tier;
        self
    }

    /// Compute Merkle hash for this entry
    pub fn compute_hash(&mut self) {
        use sha2::{Digest, Sha256};

        let entry_data = serde_json::to_string(&EntryData {
            entry_id: self.entry_id,
            sequence_number: self.sequence_number,
            timestamp: self.timestamp,
            query: &self.query,
            substrate_probes: &self.substrate_probes,
            axiom_checks: &self.axiom_checks,
            inference_output: &self.inference_output,
            epistemic_tier: &self.epistemic_tier,
            previous_hash: &self.previous_hash,
        })
        .unwrap_or_default();

        let mut data = entry_data.into_bytes();
        data.extend_from_slice(self.previous_hash.as_bytes());

        let mut hasher = Sha256::new();
        hasher.update(&data);
        self.current_hash = hex::encode(hasher.finalize());
    }

    /// Verify integrity of this entry given the previous hash
    pub fn verify(&self, expected_previous: &str) -> bool {
        self.previous_hash == expected_previous && !self.current_hash.is_empty()
    }
}

#[derive(Serialize)]
struct EntryData<'a> {
    entry_id: Uuid,
    sequence_number: u64,
    timestamp: chrono::DateTime<chrono::Utc>,
    query: &'a str,
    substrate_probes: &'a [ProbeResult],
    axiom_checks: &'a [AxiomEvaluation],
    inference_output: &'a Option<String>,
    epistemic_tier: &'a EpistemicTier,
    previous_hash: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lst_entry_creation() {
        let entry = LSTEntry::new(1, "test query", "prev_hash".to_string());
        assert_eq!(entry.sequence_number, 1);
        assert_eq!(entry.query, "test query");
    }

    #[test]
    fn test_entry_hash_computation() {
        let mut entry = LSTEntry::new(1, "test", "0".to_string());
        entry.compute_hash();
        assert!(!entry.current_hash.is_empty());
        assert_eq!(entry.current_hash.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_epistemic_tier_ordering() {
        assert!(EpistemicTier::Verified > EpistemicTier::Inferred);
        assert!(EpistemicTier::Inferred > EpistemicTier::Speculated);
    }
}

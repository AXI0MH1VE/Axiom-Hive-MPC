use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Unique identifier for an axiom
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct AxiomId(Uuid);

impl AxiomId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_name(name: &str) -> Self {
        Self(Uuid::new_v5(&Uuid::NAMESPACE_DNS, name.as_bytes()))
    }
}

impl Default for AxiomId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AxiomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Priority level for axiom evaluation (higher = evaluated first)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Priority(pub u8);

impl Priority {
    pub const CRITICAL: Self = Priority(255);
    pub const HIGH: Self = Priority(200);
    pub const NORMAL: Self = Priority(128);
    pub const LOW: Self = Priority(64);
    pub const MINIMAL: Self = Priority(1);
}

impl Default for Priority {
    fn default() -> Self {
        Priority::NORMAL
    }
}

/// Result of axiom evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AxiomResult {
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "violation")]
    Violation {
        code: String,
        message: String,
        #[serde(default)]
        remediation: Option<String>,
    },
}

impl AxiomResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, AxiomResult::Pass)
    }

    pub fn is_violation(&self) -> bool {
        matches!(self, AxiomResult::Violation { .. })
    }
}

impl fmt::Display for AxiomResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AxiomResult::Pass => write!(f, "PASS"),
            AxiomResult::Violation { code, message, .. } => {
                write!(f, "VIOLATION[{}]: {}", code, message)
            }
        }
    }
}

/// Detailed record of axiom evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AxiomEvaluation {
    pub axiom_id: AxiomId,
    pub axiom_name: String,
    pub result: AxiomResult,
    pub priority: Priority,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub duration_ms: u64,
}

/// Violation details when axiom constraint is broken
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AxiomViolation {
    pub axiom_id: AxiomId,
    pub axiom_name: String,
    pub code: String,
    pub message: String,
    pub remediation: Option<String>,
}

/// Core axiom trait - defines constraint rules for substrate states
pub trait Axiom: Send + Sync {
    /// Unique identifier for this axiom
    fn id(&self) -> AxiomId;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Priority for evaluation order (higher = evaluated first)
    fn priority(&self) -> Priority {
        Priority::default()
    }

    /// Evaluate substrate state against this axiom
    fn evaluate(&self, state: &crate::SubstrateState) -> AxiomResult;

    /// Check if this axiom should be applied to the given context
    fn is_applicable(&self, _context: &AxiomContext) -> bool {
        true
    }
}

/// Context information for axiom evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AxiomContext {
    pub query: String,
    pub user_context: Option<String>,
    pub deployment_context: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_axiom_id_deterministic() {
        let id1 = AxiomId::from_name("test_axiom");
        let id2 = AxiomId::from_name("test_axiom");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::CRITICAL > Priority::HIGH);
        assert!(Priority::HIGH > Priority::NORMAL);
        assert!(Priority::NORMAL > Priority::LOW);
        assert!(Priority::LOW > Priority::MINIMAL);
    }

    #[test]
    fn test_axiom_result_serialization() {
        let pass_result = AxiomResult::Pass;
        let json = serde_json::to_string(&pass_result).unwrap();
        assert!(json.contains("\"type\":\"pass\""));

        let violation = AxiomResult::Violation {
            code: "TEST_VIOLATION".to_string(),
            message: "Test message".to_string(),
            remediation: None,
        };
        let json = serde_json::to_string(&violation).unwrap();
        assert!(json.contains("TEST_VIOLATION"));
    }
}

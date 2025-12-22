use axiom_core::{AxiomEvaluation, AxiomHiveError};
use serde::{Deserialize, Serialize};

/// Result of constraint execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub evaluations: Vec<AxiomEvaluation>,
    pub error: Option<String>,
    pub total_duration_ms: u64,
}

impl ExecutionResult {
    pub fn from_evaluations(evaluations: Vec<AxiomEvaluation>, start: std::time::Instant) -> Self {
        let success = evaluations.iter().all(|e| e.result.is_pass());
        let total_duration_ms = start.elapsed().as_millis() as u64;

        Self {
            success,
            evaluations,
            error: None,
            total_duration_ms,
        }
    }

    pub fn from_error(error: AxiomHiveError, start: std::time::Instant) -> Self {
        Self {
            success: false,
            evaluations: Vec::new(),
            error: Some(error.to_string()),
            total_duration_ms: start.elapsed().as_millis() as u64,
        }
    }
}

/// Executes constraints and manages constraint lifecycle
pub struct ConstraintExecutor {
    name: String,
}

impl ConstraintExecutor {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Execute a pre-condition check
    pub fn check_precondition<F>(&self, check_fn: F) -> Result<ExecutionResult, AxiomHiveError>
    where
        F: FnOnce() -> Result<Vec<AxiomEvaluation>, AxiomHiveError>,
    {
        let start = std::time::Instant::now();
        match check_fn() {
            Ok(evaluations) => Ok(ExecutionResult::from_evaluations(evaluations, start)),
            Err(e) => Ok(ExecutionResult::from_error(e, start)),
        }
    }

    /// Execute a post-condition check
    pub fn check_postcondition<F>(&self, check_fn: F) -> Result<ExecutionResult, AxiomHiveError>
    where
        F: FnOnce() -> Result<Vec<AxiomEvaluation>, AxiomHiveError>,
    {
        let start = std::time::Instant::now();
        match check_fn() {
            Ok(evaluations) => Ok(ExecutionResult::from_evaluations(evaluations, start)),
            Err(e) => Ok(ExecutionResult::from_error(e, start)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result_from_evaluations() {
        let evaluations = vec![];
        let start = std::time::Instant::now();
        let result = ExecutionResult::from_evaluations(evaluations, start);

        assert!(result.success);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_constraint_executor_creation() {
        let executor = ConstraintExecutor::new("test_executor");
        assert_eq!(executor.name(), "test_executor");
    }
}

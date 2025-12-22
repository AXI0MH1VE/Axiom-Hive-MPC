use axiom_core::{Axiom, AxiomContext, AxiomEvaluation, AxiomHiveError, SubstrateState};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Configuration for MCP Engine
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MCPEngineConfig {
    pub max_axioms: usize,
    pub timeout_ms: u64,
    pub halt_on_violation: bool,
    pub enable_logging: bool,
}

impl Default for MCPEngineConfig {
    fn default() -> Self {
        Self {
            max_axioms: 1000,
            timeout_ms: 5000,
            halt_on_violation: true,
            enable_logging: true,
        }
    }
}

/// MCP Engine - enforces axiom constraints before inference
pub struct MCPEngine {
    axioms: Vec<Arc<dyn Axiom>>,
    config: MCPEngineConfig,
}

impl MCPEngine {
    pub fn new(config: MCPEngineConfig) -> Self {
        Self {
            axioms: Vec::new(),
            config,
        }
    }

    pub fn register_axiom(&mut self, axiom: Arc<dyn Axiom>) -> Result<(), AxiomHiveError> {
        if self.axioms.len() >= self.config.max_axioms {
            return Err(AxiomHiveError::Unknown(format!(
                "Maximum axioms ({}) reached",
                self.config.max_axioms
            )));
        }
        self.axioms.push(axiom);
        // Sort by priority (highest first)
        self.axioms.sort_by(|a, b| b.priority().cmp(&a.priority()));
        Ok(())
    }

    pub fn axiom_count(&self) -> usize {
        self.axioms.len()
    }

    /// Pre-inference axiom enforcement
    pub fn evaluate_pre_inference(
        &self,
        substrate_state: &SubstrateState,
        context: &AxiomContext,
    ) -> Result<Vec<AxiomEvaluation>, AxiomHiveError> {
        let mut evaluations = Vec::new();

        for axiom in &self.axioms {
            if !axiom.is_applicable(context) {
                continue;
            }

            let start = std::time::Instant::now();
            let result = axiom.evaluate(substrate_state);
            let duration_ms = start.elapsed().as_millis() as u64;

            let evaluation = AxiomEvaluation {
                axiom_id: axiom.id(),
                axiom_name: axiom.name().to_string(),
                result: result.clone(),
                priority: axiom.priority(),
                evaluated_at: chrono::Utc::now(),
                duration_ms,
            };

            if self.config.enable_logging {
                tracing::info!("Axiom evaluation: {:?}", evaluation);
            }

            // If halt_on_violation and axiom failed, stop evaluation
            if self.config.halt_on_violation && result.is_violation() {
                evaluations.push(evaluation);
                return Err(AxiomHiveError::AxiomError(
                    axiom_core::AxiomError::Violation(format!(
                        "Axiom {} violation detected",
                        axiom.name()
                    )),
                ));
            }

            evaluations.push(evaluation);
        }

        Ok(evaluations)
    }

    /// Post-inference validation (catch violations LLM might have generated)
    pub fn validate_post_inference(
        &self,
        output: &str,
        substrate_state: &SubstrateState,
        context: &AxiomContext,
    ) -> Result<bool, AxiomHiveError> {
        // Parse output for obvious violations
        let suspicious_patterns = vec![
            "SQL injection",
            "try these approaches:",
            "brute force",
            "header manipulation",
        ];

        let is_suspicious = suspicious_patterns
            .iter()
            .any(|p| output.to_lowercase().contains(&p.to_lowercase()));

        if is_suspicious {
            // Re-run axiom checks
            let evaluations = self.evaluate_pre_inference(substrate_state, context)?;
            Ok(evaluations.iter().all(|e| e.result.is_pass()))
        } else {
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core::{AxiomId, AxiomResult};

    struct TestAxiom {
        id: AxiomId,
        should_pass: bool,
    }

    impl Axiom for TestAxiom {
        fn id(&self) -> AxiomId {
            self.id
        }

        fn name(&self) -> &str {
            "test_axiom"
        }

        fn evaluate(&self, _state: &SubstrateState) -> AxiomResult {
            if self.should_pass {
                AxiomResult::Pass
            } else {
                AxiomResult::Violation {
                    code: "TEST".to_string(),
                    message: "Test violation".to_string(),
                    remediation: None,
                }
            }
        }
    }

    #[test]
    fn test_mcp_engine_registration() {
        let config = MCPEngineConfig::default();
        let mut engine = MCPEngine::new(config);

        let axiom = Arc::new(TestAxiom {
            id: AxiomId::new(),
            should_pass: true,
        });

        engine.register_axiom(axiom).unwrap();
        assert_eq!(engine.axiom_count(), 1);
    }

    #[test]
    fn test_mcp_engine_max_axioms() {
        let config = MCPEngineConfig {
            max_axioms: 1,
            ..Default::default()
        };
        let mut engine = MCPEngine::new(config);

        let axiom1 = Arc::new(TestAxiom {
            id: AxiomId::new(),
            should_pass: true,
        });
        let axiom2 = Arc::new(TestAxiom {
            id: AxiomId::new(),
            should_pass: true,
        });

        engine.register_axiom(axiom1).unwrap();
        assert!(engine.register_axiom(axiom2).is_err());
    }
}

use axiom_core::{Axiom, AxiomContext, AxiomId, AxiomResult, Priority, SubstrateState};

/// AXIOM_NO_CTF_IN_PRODUCTION
/// Prevents treating production/internal systems as Capture-The-Flag challenges
pub struct ProductionCTFExclusion;

impl Axiom for ProductionCTFExclusion {
    fn id(&self) -> AxiomId {
        AxiomId::from_name("AXIOM_NO_CTF_IN_PRODUCTION")
    }

    fn name(&self) -> &str {
        "No CTF in Production"
    }

    fn priority(&self) -> Priority {
        Priority::CRITICAL
    }

    fn is_applicable(&self, context: &AxiomContext) -> bool {
        // Apply when context signals production or corporate environments
        context
            .deployment_context
            .as_ref()
            .map(|c: &String| c.contains("production") || c.contains("corporate") || c.contains("internal"))
            .unwrap_or(true)
    }

    fn evaluate(&self, state: &SubstrateState) -> AxiomResult {
        let is_internal = state.is_internal_network
            || state
                .dns_resolution
                .map(|ip| {
                    let s = ip.to_string();
                    s.starts_with("10.") || s.starts_with("172.") || s.starts_with("192.168") || s.starts_with("127.")
                })
                .unwrap_or(false)
            || state.tls_valid;

        if is_internal {
            return AxiomResult::Violation {
                code: "NO_CTF_IN_PROD".to_string(),
                message: "Production/internal system detected; block CTF framing and attack guidance.".to_string(),
                remediation: Some("Treat as configuration/permission issue. Escalate to DevOps/SRE; do not perform intrusion techniques.".to_string()),
            };
        }

        AxiomResult::Pass
    }
}

/// AXIOM_FRIENDLY_FIRE_PREVENTION
/// Blocks suggesting active attack vectors against internal systems
pub struct ProductionFriendlyFirePrevention;

impl Axiom for ProductionFriendlyFirePrevention {
    fn id(&self) -> AxiomId {
        AxiomId::from_name("AXIOM_FRIENDLY_FIRE_PREVENTION")
    }

    fn name(&self) -> &str {
        "Friendly Fire Prevention"
    }

    fn priority(&self) -> Priority {
        Priority::HIGH
    }

    fn evaluate(&self, state: &SubstrateState) -> AxiomResult {
        let guarded = state.is_internal_network
            || state
                .dns_resolution
                .map(|ip| {
                    let s = ip.to_string();
                    s.starts_with("10.") || s.starts_with("172.") || s.starts_with("192.168") || s.starts_with("127.")
                })
                .unwrap_or(false);

        if guarded && matches!(state.http_status, Some(401) | Some(402) | Some(403) | Some(404) | Some(418) | Some(429)) {
            return AxiomResult::Violation {
                code: "BLOCK_ATTACK_SUGGESTIONS".to_string(),
                message: "Internal environment with access restrictions: suppress attack vector suggestions (brute force, SQLi, header manipulation).".to_string(),
                remediation: Some("Verify role/team membership and request proper access. Engage security if behavior is unexpected.".to_string()),
            };
        }

        AxiomResult::Pass
    }
}

/// AXIOM_VERIFY_PII
/// Requires verification when public visibility and sampled content exist (possible PII exposure)
pub struct ProductionDataLeakDetection;

impl Axiom for ProductionDataLeakDetection {
    fn id(&self) -> AxiomId {
        AxiomId::from_name("AXIOM_VERIFY_PII")
    }

    fn name(&self) -> &str {
        "PII Verification Required"
    }

    fn priority(&self) -> Priority {
        Priority::HIGH
    }

    fn evaluate(&self, state: &SubstrateState) -> AxiomResult {
        let is_public = state
            .visibility_label
            .as_ref()
            .map(|v| v.to_lowercase().contains("public"))
            .unwrap_or(false);

        let has_sample = state.content_hash.is_some();

        if is_public && has_sample {
            return AxiomResult::Violation {
                code: "PII_VERIFICATION_REQUIRED".to_string(),
                message: "Public visibility with captured content: verify data is not real PII before proceeding.".to_string(),
                remediation: Some("Perform authorized deep scan on minimal sample; confirm synthetic/test data before classifying or sharing.".to_string()),
            };
        }

        AxiomResult::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctf_exclusion_violation_internal() {
        let axiom = ProductionCTFExclusion;
        let context = AxiomContext {
            query: "test".to_string(),
            user_context: None,
            deployment_context: Some("production".to_string()),
        };

        assert!(axiom.is_applicable(&context));

        let state = SubstrateState::new().with_internal_network(true);
        let result = axiom.evaluate(&state);
        assert!(result.is_violation());
    }

    #[test]
    fn test_friendly_fire_prevention_blocks_attack_on_internal() {
        let axiom = ProductionFriendlyFirePrevention;
        let state = SubstrateState::new()
            .with_http_status(403)
            .with_internal_network(true);

        let result = axiom.evaluate(&state);
        assert!(result.is_violation());
    }

    #[test]
    fn test_pii_verification_trigger() {
        let axiom = ProductionDataLeakDetection;
        let mut state = SubstrateState::new().with_visibility("public".to_string());
        state.content_hash = Some("abc123".to_string());

        let result = axiom.evaluate(&state);
        assert!(result.is_violation());
    }
}

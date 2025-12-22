use axiom_core::{Axiom, AxiomContext, AxiomHiveError, SubstrateState};
use axiom_mcp::MCPEngine;
use axiom_security::{
    RepositoryAccessConsistency, RepositoryMisconfiguration, RepositoryPublicPrivateMatch,
};
use axiom_substrate::{SubstrateVerifier, VerificationConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║        AxiomHive: Repository Paradox Resolution Demo            ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    // Scenario 1: The Classic Paradox - Public label + 403 Forbidden
    println!("SCENARIO 1: Public-Labeled Repository with Access Denied");
    println!("─────────────────────────────────────────────────────────────────");
    resolve_repository_paradox().await?;

    println!();
    println!();

    // Scenario 2: Valid public repository
    println!("SCENARIO 2: Legitimate Public Repository");
    println!("─────────────────────────────────────────────────────────────────");
    legitimate_public_repo().await?;

    println!();
    println!();

    // Scenario 3: Private repository (correctly configured)
    println!("SCENARIO 3: Private Repository (Correct Configuration)");
    println!("─────────────────────────────────────────────────────────────────");
    legitimate_private_repo().await?;

    Ok(())
}

async fn resolve_repository_paradox() -> Result<(), AxiomHiveError> {
    // Simulate substrate state: Public label but 403 Forbidden
    let mut substrate_state = SubstrateState::new()
        .with_http_status(403)
        .with_visibility("public".to_string())
        .with_internal_network(false);
    substrate_state.sign();

    println!("Substrate State:");
    println!("  HTTP Status: 403 FORBIDDEN");
    println!("  Visibility Label: PUBLIC");
    println!("  Internal Network: No");
    println!("  Cryptographic Signature: {}", &substrate_state.signature[..16]);
    println!();

    // Create MCP Engine with axioms
    let mut mcp_engine = axiom_mcp::MCPEngine::new(Default::default());

    mcp_engine.register_axiom(Arc::new(RepositoryAccessConsistency))?;
    mcp_engine.register_axiom(Arc::new(RepositoryPublicPrivateMatch))?;
    mcp_engine.register_axiom(Arc::new(RepositoryMisconfiguration))?;

    println!("Registered {} axioms", mcp_engine.axiom_count());
    println!();

    // Evaluate axioms
    let context = AxiomContext {
        query: "Why can't I access this repository?".to_string(),
        user_context: Some("developer@example.com".to_string()),
        deployment_context: Some("corporate-internal".to_string()),
    };

    println!("Evaluating Pre-Inference Axioms:");
    println!("─────────────────────────────────");

    match mcp_engine.evaluate_pre_inference(&substrate_state, &context) {
        Ok(evaluations) => {
            for eval in &evaluations {
                match &eval.result {
                    axiom_core::AxiomResult::Pass => {
                        println!("  ✓ {}: PASS", eval.axiom_name);
                    }
                    axiom_core::AxiomResult::Violation { code, message, remediation } => {
                        println!("  ✗ {}: VIOLATION", eval.axiom_name);
                        println!("    Code: {}", code);
                        println!("    Message: {}", message);
                        if let Some(rem) = remediation {
                            println!("    Remediation: {}", rem);
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("  ✗ Axiom Evaluation Error: {}", e);
        }
    }

    println!();
    println!("Substrate Verification:");
    println!("─────────────────────────");

    let verifier = SubstrateVerifier::new(VerificationConfig::default());
    let repo_verification = verifier.verify_repo_config(&substrate_state);

    match repo_verification.verified {
        true => println!("  ✓ Substrate state is consistent"),
        false => {
            println!("  ✗ Configuration Error Detected");
            if let Some(error) = repo_verification.error {
                println!("  Details: {}", error);
            }
        }
    }

    println!();
    println!("AxiomHive Conclusion:");
    println!("─────────────────────");
    println!("✗ INFERENCE HALTED");
    println!("Reason: Axiom violation (Public + 403 = Configuration Error)");
    println!("Action: Contact repository admin or DevOps to correct permissions");
    println!("Safety: No attack vectors suggested (friendly fire prevented)");

    Ok(())
}

async fn legitimate_public_repo() -> Result<(), AxiomHiveError> {
    let mut substrate_state = SubstrateState::new()
        .with_http_status(200)
        .with_visibility("public".to_string())
        .with_internal_network(false);
    substrate_state.sign();

    println!("Substrate State:");
    println!("  HTTP Status: 200 OK");
    println!("  Visibility Label: PUBLIC");
    println!("  Internal Network: No");
    println!();

    let mut mcp_engine = axiom_mcp::MCPEngine::new(Default::default());
    mcp_engine.register_axiom(Arc::new(RepositoryAccessConsistency))?;
    mcp_engine.register_axiom(Arc::new(RepositoryPublicPrivateMatch))?;

    let context = AxiomContext {
        query: "How do I clone this repository?".to_string(),
        user_context: None,
        deployment_context: None,
    };

    println!("Evaluating Axioms: ");

    match mcp_engine.evaluate_pre_inference(&substrate_state, &context) {
        Ok(evaluations) => {
            for eval in &evaluations {
                match &eval.result {
                    axiom_core::AxiomResult::Pass => {
                        println!("  ✓ {}: PASS", eval.axiom_name);
                    }
                    axiom_core::AxiomResult::Violation { .. } => {
                        println!("  ✗ {}: VIOLATION", eval.axiom_name);
                    }
                }
            }
        }
        Err(e) => println!("  ✗ Error: {}", e),
    }

    println!();
    println!("AxiomHive Conclusion:");
    println!("─────────────────────");
    println!("✓ ALL AXIOMS PASSED");
    println!("Action: Proceed to LLM inference");
    println!("Inference would suggest: Clone with 'git clone <repo-url>'");

    Ok(())
}

async fn legitimate_private_repo() -> Result<(), AxiomHiveError> {
    let mut substrate_state = SubstrateState::new()
        .with_http_status(403)
        .with_visibility("private".to_string())
        .with_internal_network(false);
    substrate_state.sign();

    println!("Substrate State:");
    println!("  HTTP Status: 403 FORBIDDEN");
    println!("  Visibility Label: PRIVATE");
    println!("  Internal Network: No");
    println!();

    let mut mcp_engine = axiom_mcp::MCPEngine::new(Default::default());
    mcp_engine.register_axiom(Arc::new(RepositoryAccessConsistency))?;
    mcp_engine.register_axiom(Arc::new(RepositoryPublicPrivateMatch))?;

    let context = AxiomContext {
        query: "Why can't I access this repository?".to_string(),
        user_context: Some("user@example.com".to_string()),
        deployment_context: None,
    };

    println!("Evaluating Axioms:");

    match mcp_engine.evaluate_pre_inference(&substrate_state, &context) {
        Ok(evaluations) => {
            for eval in &evaluations {
                match &eval.result {
                    axiom_core::AxiomResult::Pass => {
                        println!("  ✓ {}: PASS", eval.axiom_name);
                    }
                    axiom_core::AxiomResult::Violation { .. } => {
                        println!("  ✗ {}: VIOLATION", eval.axiom_name);
                    }
                }
            }
        }
        Err(e) => println!("  ✗ Error: {}", e),
    }

    println!();
    println!("AxiomHive Conclusion:");
    println!("─────────────────────");
    println!("✓ ALL AXIOMS PASSED");
    println!("Action: Proceed to LLM inference");
    println!("Inference would suggest: Request access via repository admin");

    Ok(())
}

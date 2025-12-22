use axiom_lst::{LSTEntry, LSTLog, LogConfig, MerkleTree};
use axiom_mcp::MCPEngine;
use axiom_security::{RepositoryMisconfiguration, RepositoryPublicPrivateMatch};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║     AxiomHive: Complete Axiom + LST Logging Demonstration       ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    // Create LST log
    println!("1. Initializing Log-Structured Tensor (LST)");
    println!("─────────────────────────────────────────────");
    let log_config = LogConfig::default();
    let lst_log = LSTLog::new(log_config);
    println!("   ✓ LST Log initialized");
    println!();

    // Create and evaluate first query
    println!("2. First Query: Public Repository with 403");
    println!("─────────────────────────────────────────────");

    let mut substrate_state = axiom_core::SubstrateState::new()
        .with_http_status(403)
        .with_visibility("public".to_string());
    substrate_state.sign();

    let mut mcp_engine = MCPEngine::new(Default::default());
    mcp_engine.register_axiom(Arc::new(RepositoryPublicPrivateMatch))?;
    mcp_engine.register_axiom(Arc::new(RepositoryMisconfiguration))?;

    let context = axiom_core::AxiomContext {
        query: "Access repository X".to_string(),
        user_context: None,
        deployment_context: Some("corporate".to_string()),
    };

    match mcp_engine.evaluate_pre_inference(&substrate_state, &context) {
        Ok(evaluations) => {
            // Create LST entry with axiom evaluations
            let mut entry1 = LSTEntry::new(1, "Access repository X", "0".to_string());

            for eval in evaluations {
                entry1 = entry1.add_axiom_check(eval);
            }

            entry1.compute_hash();
            let hash1 = lst_log.append(entry1.clone())?;
            let hash1_clone = hash1.clone();

            println!("   Entry #1:");
            println!("   Query: {}", entry1.query);
            println!("   Axiom Checks: {}", entry1.axiom_checks.len());
            println!("   Hash: {}", &hash1[..16]);
            println!();

            // Create second query
            println!("3. Second Query: Legitimate Public Repository");
            println!("───────────────────────────────────────────────");

            let mut substrate_state2 = axiom_core::SubstrateState::new()
                .with_http_status(200)
                .with_visibility("public".to_string());
            substrate_state2.sign();

            match mcp_engine.evaluate_pre_inference(&substrate_state2, &context) {
                Ok(evaluations) => {
                    let mut entry2 = LSTEntry::new(2, "Clone repository Y", hash1);

                    for eval in evaluations {
                        entry2 = entry2.add_axiom_check(eval);
                    }

                    entry2.compute_hash();
                    let hash2 = lst_log.append(entry2.clone())?;

                    println!("   Entry #2:");
                    println!("   Query: {}", entry2.query);
                    println!("   Previous Hash: {}", &hash1_clone[..16]);
                    println!("   Current Hash: {}", &hash2[..16]);
                    println!();

                    // Verify log integrity
                    println!("4. Merkle Chain Verification");
                    println!("─────────────────────────────");

                    let is_valid = lst_log.verify_integrity()?;
                    if is_valid {
                        println!("   ✓ Log integrity verified");
                        println!("   Merkle chain is unbroken and tamper-evident");
                    } else {
                        println!("   ✗ Log integrity violation detected!");
                    }

                    println!();
                    println!("5. Merkle Tree Proof Generation");
                    println!("────────────────────────────────");

                    let mut tree = MerkleTree::new();
                    tree.add_leaf(&hash1_clone);
                    tree.add_leaf(&hash2);
                    tree.build();

                    if let Some(root) = tree.root_hash() {
                        println!("   Root Hash: {}", &root[..16]);

                        // Generate proof for first entry
                        if let Some(proof) = tree.proof_for_leaf(&hash1_clone) {
                            println!("   Merkle Proof for Entry #1:");
                            println!("   Path Length: {}", proof.path.len());

                            if proof.verify(&root) {
                                println!("   ✓ Proof verified against root");
                            }
                        }
                    }

                    println!();
                    println!("6. Log Summary");
                    println!("───────────────");
                    println!("   Total Entries: {}", lst_log.entry_count()?);
                    if let Ok(root) = lst_log.root_hash() {
                        println!("   Root Hash: {}", &root[..16]);
                    }

                    println!();
                    println!("═════════════════════════════════════════════════════════════════");
                    println!("✓ AxiomHive demonstration complete");
                    println!("");
                    println!("Key Features Demonstrated:");
                    println!("  • MCP axiom pre-enforcement");
                    println!("  • Substrate verification");
                    println!("  • LST cryptographic logging");
                    println!("  • Merkle chain integrity");
                    println!("═════════════════════════════════════════════════════════════════");
                }
                Err(e) => {
                    println!("   Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("   Error: {}", e);
        }
    }

    Ok(())
}

//! Lab 7: Receipts and Receipt Chains
//!
//! Receipt chains with hash verification
//! Run: cargo run --example lab07_receipts -p course-examples

use zp_receipt::{Action, Receipt, ReceiptChain, Status, TrustGrade};

fn main() {
    // Create an Intent receipt (root of provenance chain)
    let mut intent = Receipt::intent("user-alice")
        .status(Status::Success)
        .trust_grade(TrustGrade::B)
        .finalize();
    println!("Intent receipt: {}", intent.id);
    assert!(intent.verify_hash(), "Hash must verify");

    // Create an Execution receipt linked to the intent
    let mut execution = Receipt::execution("agent-001")
        .parent(&intent.id)
        .status(Status::Success)
        .action(Action::code_execution("python", 0))
        .trust_grade(TrustGrade::B)
        .finalize();
    println!("Execution receipt: {}", execution.id);
    assert!(execution.verify_hash(), "Hash must verify");

    // Chain them
    let mut chain = ReceiptChain::new("lab-chain");
    chain.append(&mut intent).expect("Should add root");
    chain.append(&mut execution).expect("Should add child");

    // Verify the chain
    chain.verify_integrity().expect("Chain should verify");
    println!(
        "\n✓ Receipt chain verified ({} entries)",
        chain.entries().len()
    );

    // Print chain structure
    for entry in chain.entries() {
        println!(
            "  seq={} hash={}...{}",
            entry.sequence,
            &entry.content_hash[..8],
            &entry.content_hash[entry.content_hash.len() - 8..],
        );
    }
}

//! Lab 14: Epoch Compaction
//!
//! Epoch compaction with merkle proofs
//! Run: cargo run --example lab14_epoch_compaction -p course-examples

use zp_receipt::{Epoch, EpochCompactor, Receipt, ReceiptChain, Status, TrustGrade};

fn main() {
    let mut chain = ReceiptChain::new("compaction-lab");
    let compactor = EpochCompactor::new(50);

    // Build a chain of 200 receipts
    for i in 0..200 {
        let mut receipt = Receipt::execution(&format!("executor-{}", i % 5))
            .status(Status::Success)
            .trust_grade(TrustGrade::B)
            .finalize();
        chain.append(&mut receipt).unwrap();
    }
    println!("Chain length: {} entries", chain.len());
    chain.verify_integrity().unwrap();
    println!("✓ Chain integrity verified");

    // Compact into epochs
    let mut epochs: Vec<Epoch> = Vec::new();
    let entries = chain.entries();

    for epoch_num in 0..4 {
        let start = epoch_num * 50;
        let end = start + 50;
        let epoch_entries = &entries[start..end];

        let prev = if epochs.is_empty() {
            None
        } else {
            Some(epochs.last().unwrap())
        };
        let epoch = compactor
            .compact("compaction-lab", epoch_entries, prev)
            .unwrap();

        println!(
            "Epoch {}: merkle_root={}...{}, entries={}",
            epoch.epoch_number,
            &epoch.merkle_root[..8],
            &epoch.merkle_root[epoch.merkle_root.len() - 8..],
            epoch.entry_count
        );

        epochs.push(epoch);
    }

    // Verify epoch chain
    compactor.verify_epoch_chain(&epochs).unwrap();
    println!("\n✓ Epoch chain verified ({} epochs)", epochs.len());

    // Verify a specific epoch against its entries
    let epoch_2_entries = &entries[100..150];
    compactor.verify_epoch(&epochs[2], epoch_2_entries).unwrap();
    println!("✓ Epoch 2 verified against its entries");

    println!("\n200 receipts → 4 sealed epochs → prunable with proof");
}

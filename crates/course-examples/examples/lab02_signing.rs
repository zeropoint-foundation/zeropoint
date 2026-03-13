//! Lab 2: Trust Hierarchy and Signing
//!
//! Ed25519 signing and verification
//! Run: cargo run --example lab02_signing -p course-examples

use zp_trust::Signer;

fn main() {
    let signer = Signer::generate();
    println!("Public key: {}", hex::encode(signer.public_key()));

    let message = b"This agent is authorized to read /data/reports/*";
    let signature = signer.sign(message);
    println!("Signature: {}...{}", &signature[..16], &signature[signature.len()-16..]);

    let valid = Signer::verify(&signer.public_key(), message, &signature)
        .expect("Verification should not error");
    assert!(valid, "Signature must verify");
    println!("✓ Signature verified");

    let tampered = b"This agent is authorized to read /data/secrets/*";
    let still_valid = Signer::verify(&signer.public_key(), tampered, &signature)
        .expect("Verification should not error");
    assert!(!still_valid, "Tampered message must not verify");
    println!("✓ Tampered message correctly rejected");

    let bad_sig = signature.clone();
    let bytes: Vec<u8> = hex::decode(&bad_sig).unwrap();
    let mut flipped = bytes;
    flipped[0] ^= 0xFF;
    let bad_sig = hex::encode(flipped);
    let still_valid = Signer::verify(&signer.public_key(), message, &bad_sig)
        .unwrap_or(false);
    assert!(!still_valid, "Tampered signature must not verify");
    println!("✓ Tampered signature correctly rejected");

    let secret = signer.secret_key();
    let restored = Signer::from_secret(&secret)
        .expect("Should restore from secret");
    assert_eq!(signer.public_key(), restored.public_key());
    println!("✓ Signer restored from secret key");

    let signer2 = Signer::generate();
    let sig_from_signer2 = signer2.sign(message);
    let cross_verify = Signer::verify(&signer.public_key(), message, &sig_from_signer2)
        .unwrap_or(false);
    assert!(!cross_verify, "Different signer's signature must not verify");
    println!("✓ Cross-verification correctly rejected");
}

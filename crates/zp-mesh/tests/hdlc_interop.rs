//! HDLC Wire-Format Interop Test
//!
//! Connects to the Python HDLC interop server and proves that ZeroPoint's
//! Rust HDLC codec produces bytes identical to Reticulum's Python HDLC codec.
//!
//! Run the Python server first:
//!   python3 tests/reticulum-tests/reticulum/hdlc_interop_server.py --port 7331
//!
//! Then run this test:
//!   cargo test --package zp-mesh --test hdlc_interop -- --nocapture
//!
//! Or use the runner script:
//!   bash tests/reticulum-tests/reticulum/run_hdlc_interop.sh

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use sha2::{Digest, Sha256};

use zp_mesh::tcp::{hdlc_frame, HdlcDecoder};

// =============================================================================
// Test Vectors — must match Python's generate_test_vectors() EXACTLY
// =============================================================================

fn generate_test_vectors() -> Vec<Vec<u8>> {
    let mut vectors: Vec<Vec<u8>> = Vec::new();

    // 1. Simple ASCII — no escaping needed
    vectors.push(b"hello reticulum".to_vec());

    // 2. Contains FLAG byte (0x7E) — must be escaped
    vectors.push(vec![0x01, 0x02, 0x7E, 0x03, 0x04]);

    // 3. Contains ESC byte (0x7D) — must be escaped
    vectors.push(vec![0x10, 0x7D, 0x20, 0x30]);

    // 4. Contains BOTH FLAG and ESC — double trouble
    vectors.push(vec![0x7E, 0x7D, 0x7E, 0x7D]);

    // 5. All special bytes consecutively
    vectors.push(vec![0x7E, 0x7E, 0x7E, 0x7D, 0x7D, 0x7D]);

    // 6. Bytes that look like escaped sequences but aren't
    //    0x5E = FLAG ^ ESC_MASK, 0x5D = ESC ^ ESC_MASK
    vectors.push(vec![0x5E, 0x5D, 0x5E, 0x5D]);

    // 7. All 256 byte values (comprehensive)
    vectors.push((0..=255u8).collect());

    // 8. Empty-ish — single byte
    vectors.push(vec![0x42]);

    // 9. Reticulum-realistic: simulated packet header + payload
    let header = vec![0b00000000u8, 0x07];
    let dest_hash: Vec<u8> = {
        let mut hasher = Sha256::new();
        hasher.update(b"test-destination");
        hasher.finalize()[..16].to_vec()
    };
    let payload = b"ZeroPoint receipt data with special \x7e\x7d bytes";
    let mut v9 = Vec::new();
    v9.extend_from_slice(&header);
    v9.extend_from_slice(&dest_hash);
    v9.extend_from_slice(payload);
    vectors.push(v9);

    // 10. Maximum Reticulum MTU (500 bytes) with deterministic pseudo-random content
    //     Python uses random.Random(42), we reproduce the same sequence.
    //     Python's Random uses Mersenne Twister with seed 42.
    //     We pre-compute what Python's `random.Random(42).randint(0,255)` produces.
    //     Instead, we use the shared approach: both sides use the same generation.
    //     Since we can't easily replicate Python's MT, we'll use a different strategy:
    //     The runner script will pass the vectors as a file, OR we replicate MT.
    //
    //     Actually, for perfect interop we need to match Python's MT output exactly.
    //     Python's random.Random(42) Mersenne Twister with seed 42 produces a
    //     deterministic sequence. Let's hardcode the first vector or use a simpler
    //     deterministic function that both languages can reproduce.
    //
    //     SOLUTION: Use SHA-256 based PRNG that both Python and Rust can match:
    //     byte[i] = SHA256(b"interop-mtu-vector" || i.to_le_bytes())[0]
    let mut mtu_data = Vec::with_capacity(500);
    for i in 0u32..500 {
        let mut hasher = Sha256::new();
        hasher.update(b"interop-mtu-vector");
        hasher.update(&i.to_le_bytes());
        let hash = hasher.finalize();
        mtu_data.push(hash[0]);
    }
    vectors.push(mtu_data);

    vectors
}

// =============================================================================
// Test
// =============================================================================

/// Connect to the Python HDLC interop server and verify wire-format compatibility.
///
/// This test is ignored by default because it requires the Python server to be
/// running. Use `--ignored` flag or the runner script to execute it.
#[test]
#[ignore]
fn test_hdlc_interop_with_python() {
    let port = std::env::var("HDLC_INTEROP_PORT").unwrap_or_else(|_| "7331".into());
    let addr = format!("127.0.0.1:{}", port);

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║   HDLC Wire-Format Interop Client (ZeroPoint Rust)         ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Connecting to: {:<44}║", addr);
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Connect to Python server
    let mut stream = TcpStream::connect(&addr).expect("Failed to connect to Python HDLC server");
    stream.set_nodelay(true).expect("Failed to set TCP_NODELAY");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("Failed to set read timeout");

    println!("✓ Connected to Python server\n");

    let vectors = generate_test_vectors();
    let n_vectors = vectors.len();

    // ── Phase 1: Receive from Python ─────────────────────────────────
    println!("── Phase 1: Python → Rust ({} vectors) ──", n_vectors);

    let mut decoder = HdlcDecoder::new();
    let mut received: Vec<Vec<u8>> = Vec::new();
    let mut buf = [0u8; 65536];
    let mut phase1_done = false;

    while !phase1_done {
        let n = stream.read(&mut buf).expect("Read error in phase 1");
        if n == 0 {
            panic!("Connection closed during phase 1");
        }

        let frames = decoder.feed(&buf[..n]);
        for frame in frames {
            if frame == b"__PHASE1_COMPLETE__" {
                phase1_done = true;
                continue;
            }
            received.push(frame);
        }
    }

    // Verify received vectors
    assert_eq!(
        received.len(),
        n_vectors,
        "Expected {} vectors from Python, got {}",
        n_vectors,
        received.len()
    );

    let mut rust_verified = 0;
    for (i, (expected, actual)) in vectors.iter().zip(received.iter()).enumerate() {
        if expected == actual {
            rust_verified += 1;
            let special = actual.iter().filter(|&&b| b == 0x7E || b == 0x7D).count();
            println!(
                "  Vector {:2}: ✓ MATCH ({} bytes, {} special)",
                i + 1,
                actual.len(),
                special
            );
        } else {
            println!(
                "  Vector {:2}: ✗ MISMATCH (expected {} bytes, got {} bytes)",
                i + 1,
                expected.len(),
                actual.len()
            );
            // Find first difference
            for j in 0..std::cmp::min(expected.len(), actual.len()) {
                if expected[j] != actual[j] {
                    println!(
                        "             First diff at byte {}: expected 0x{:02x}, got 0x{:02x}",
                        j, expected[j], actual[j]
                    );
                    break;
                }
            }
        }
    }

    assert_eq!(
        rust_verified, n_vectors,
        "Only {}/{} vectors matched",
        rust_verified, n_vectors
    );

    println!(
        "\n  ✓ All {} vectors from Python decoded correctly by Rust\n",
        n_vectors
    );

    // ── Phase 2: Send to Python ──────────────────────────────────────
    println!("── Phase 2: Rust → Python ({} vectors) ──", n_vectors);

    for (i, payload) in vectors.iter().enumerate() {
        let frame = hdlc_frame(payload);
        stream.write_all(&frame).expect("Write error in phase 2");
        println!(
            "  Sent vector {:2}: {:4} raw → {:4} framed",
            i + 1,
            payload.len(),
            frame.len()
        );
    }

    // Send phase 2 sentinel
    let sentinel_frame = hdlc_frame(b"__PHASE2_COMPLETE__");
    stream
        .write_all(&sentinel_frame)
        .expect("Write sentinel error");
    stream.flush().expect("Flush error");
    println!("  Sent phase-2 sentinel");

    // ── Phase 3: Receive Python's verdict ────────────────────────────
    println!("\n── Phase 3: Awaiting Python verification ──");

    let mut decoder2 = HdlcDecoder::new();
    let mut verdict_json: Option<String> = None;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while verdict_json.is_none() && std::time::Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let frames = decoder2.feed(&buf[..n]);
                for frame in frames {
                    if let Ok(s) = String::from_utf8(frame) {
                        if s.contains("python_verified") {
                            verdict_json = Some(s);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => panic!("Read error waiting for verdict: {}", e),
        }
    }

    let verdict = verdict_json.expect("Never received Python's verification verdict");
    println!("  Python verdict: {}", verdict);

    // Parse and verify
    let v: serde_json::Value = serde_json::from_str(&verdict).expect("Invalid JSON verdict");
    let py_pass = v["pass"].as_bool().unwrap_or(false);
    let py_verified = v["python_verified"].as_u64().unwrap_or(0);

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  INTEROP RESULTS:");
    println!(
        "    Rust decoded Python frames: {}/{} ✓",
        rust_verified, n_vectors
    );
    println!(
        "    Python decoded Rust frames: {}/{} {}",
        py_verified,
        n_vectors,
        if py_pass { "✓" } else { "✗" }
    );
    println!(
        "    Wire format:                {}",
        if py_pass && rust_verified == n_vectors {
            "COMPATIBLE ✓"
        } else {
            "INCOMPATIBLE ✗"
        }
    );
    println!("═══════════════════════════════════════════════════════════════\n");

    assert!(py_pass, "Python side reported verification failure");
    assert_eq!(
        rust_verified, n_vectors,
        "Rust side verification incomplete"
    );

    println!("  ZeroPoint speaks Reticulum. Citizenship confirmed.\n");
}

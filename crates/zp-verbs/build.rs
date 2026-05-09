fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = &[
        "../../proto/v1/common.proto",
        "../../proto/v1/guard.proto",
        "../../proto/v1/delegation.proto",
        "../../proto/v1/receipts.proto",
        "../../proto/v1/audit.proto",
        "../../proto/v1/mesh.proto",
        "../../proto/v1/subscriptions.proto",
        "../../proto/v1/nodestatus.proto",
    ];

    let include_paths = &["../../proto"];

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(proto_files, include_paths)?;

    // Tell Cargo to rerun if any proto file changes
    for f in proto_files {
        println!("cargo:rerun-if-changed={}", f);
    }

    Ok(())
}

//! Trust Triangle CLI — launch a node in the cross-domain governance demo.
//!
//! Usage:
//!   # Terminal 1: Start the clinic
//!   cargo run -p trust-triangle -- --role clinic --port 3001
//!
//!   # Terminal 2: Start the pharmacy
//!   cargo run -p trust-triangle -- --role pharmacy --port 3002
//!
//!   # Terminal 3: Run the patient scenario
//!   cargo run -p trust-triangle -- --role patient --port 3003 \
//!       --clinic http://localhost:3001 \
//!       --pharmacy http://localhost:3002 \
//!       --patient-id patient-12345

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use trust_triangle::data::{ClinicDb, PharmacyDb};
use trust_triangle::display;
use trust_triangle::http_api::{self, AppState, NodeRole};
use trust_triangle::node::NodeContext;

#[derive(Parser)]
#[command(
    name = "trust-triangle",
    about = "Trust Triangle — ZeroPoint cross-domain governance demo"
)]
struct Args {
    /// Node role: clinic, pharmacy, or patient
    #[arg(long)]
    role: String,

    /// HTTP port to listen on
    #[arg(long, default_value = "3000")]
    port: u16,

    /// Clinic endpoint (patient role only)
    #[arg(long)]
    clinic: Option<String>,

    /// Pharmacy endpoint (patient role only)
    #[arg(long)]
    pharmacy: Option<String>,

    /// Patient ID to query (patient role only)
    #[arg(long, default_value = "patient-12345")]
    patient_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    match args.role.as_str() {
        "clinic" => run_clinic(args).await,
        "pharmacy" => run_pharmacy(args).await,
        "patient" => run_patient(args).await,
        other => {
            eprintln!("Unknown role: {other}. Use: clinic, pharmacy, or patient");
            std::process::exit(1);
        }
    }
}

async fn run_clinic(args: Args) -> anyhow::Result<()> {
    let ctx = NodeContext::new("clinic", "MediCare Foundation");
    display::node_started("clinic", "MediCare Clinic", args.port, &ctx.genesis_fingerprint());

    let state = Arc::new(AppState {
        ctx,
        role: NodeRole::Clinic,
        clinic_db: Some(ClinicDb::new()),
        pharmacy_db: None,
    });

    let router = http_api::router(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

async fn run_pharmacy(args: Args) -> anyhow::Result<()> {
    let ctx = NodeContext::new("pharmacy", "QuickRx Holdings");
    display::node_started(
        "pharmacy",
        "QuickRx Pharmacy",
        args.port,
        &ctx.genesis_fingerprint(),
    );

    let state = Arc::new(AppState {
        ctx,
        role: NodeRole::Pharmacy,
        clinic_db: None,
        pharmacy_db: Some(PharmacyDb::new()),
    });

    let router = http_api::router(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

async fn run_patient(args: Args) -> anyhow::Result<()> {
    let clinic_endpoint = args
        .clinic
        .unwrap_or_else(|| "http://localhost:3001".into());
    let pharmacy_endpoint = args
        .pharmacy
        .unwrap_or_else(|| "http://localhost:3002".into());

    let ctx = NodeContext::new("patient-assistant", "Patient Cloud");

    display::banner();

    trust_triangle::patient::run_scenario(
        &ctx,
        &clinic_endpoint,
        &pharmacy_endpoint,
        &args.patient_id,
    )
    .await?;

    Ok(())
}

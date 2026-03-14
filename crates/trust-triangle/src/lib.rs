//! # Trust Triangle — ZeroPoint Reference Implementation
//!
//! Demonstrates cross-domain cryptographic governance between three autonomous
//! nodes from different trust domains, communicating over plain HTTPS.
//!
//! ## Scenario
//!
//! A patient asks their personal AI assistant: "Why is my prescription late?"
//!
//! To answer, the patient's agent must coordinate with two foreign organizations:
//! - **MediCare Clinic** — holds appointment scheduling data
//! - **QuickRx Pharmacy** — holds prescription fulfillment data
//!
//! Each organization runs its own ZeroPoint genesis key. Every data exchange
//! is policy-gated, sanitized, and produces a signed cryptographic receipt.
//! The patient receives their answer along with a full provenance chain
//! proving exactly what data was accessed, by whom, and under what authority.
//!
//! ## What This Demonstrates
//!
//! - **Key hierarchy**: Three independent genesis keys → operator keys → agent keys
//! - **Introduction protocol**: Cross-genesis trust establishment (policy-gated)
//! - **Graduated policy**: Sanitize decisions strip other patients' data
//! - **Signed receipts**: Every query produces a verifiable receipt
//! - **Transport agnosticism**: All governance runs over plain HTTPS

pub mod clinic;
pub mod data;
pub mod display;
pub mod http_api;
pub mod node;
pub mod patient;
pub mod pharmacy;
pub mod types;

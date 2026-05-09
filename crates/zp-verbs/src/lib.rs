//! Generated Rust types for the ZeroPoint v1 verb set.
//!
//! This crate is the codegen target for `proto/v1/*.proto`. It exposes
//! generated types (request/response messages, gRPC client/server
//! traits) for each service. Downstream crates depend on `zp-verbs`
//! for typed access to the verb-set schema.
//!
//! Per Architecture II.0, this is a port crate — singular schema source.
//! Per Architecture II.7, protobuf is the schema layer.
//!
//! Module layout matches proto packages:
//!   zeropoint.v1.common        → zp_verbs::common
//!   zeropoint.v1.guard         → zp_verbs::guard
//!   zeropoint.v1.delegation    → zp_verbs::delegation
//!   zeropoint.v1.receipts      → zp_verbs::receipts
//!   zeropoint.v1.audit         → zp_verbs::audit
//!   zeropoint.v1.mesh          → zp_verbs::mesh
//!   zeropoint.v1.subscriptions → zp_verbs::subscriptions
//!   zeropoint.v1.nodestatus    → zp_verbs::nodestatus

pub mod common {
    tonic::include_proto!("zeropoint.v1.common");
}

pub mod guard {
    tonic::include_proto!("zeropoint.v1.guard");
}

pub mod delegation {
    tonic::include_proto!("zeropoint.v1.delegation");
}

pub mod receipts {
    tonic::include_proto!("zeropoint.v1.receipts");
}

pub mod audit {
    tonic::include_proto!("zeropoint.v1.audit");
}

pub mod mesh {
    tonic::include_proto!("zeropoint.v1.mesh");
}

pub mod subscriptions {
    tonic::include_proto!("zeropoint.v1.subscriptions");
}

pub mod nodestatus {
    tonic::include_proto!("zeropoint.v1.nodestatus");
}

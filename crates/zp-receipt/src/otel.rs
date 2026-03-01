//! OpenTelemetry span export for receipts.
//!
//! Converts ZeroPoint receipts into OTEL spans that can be exported to
//! any OTEL-compatible backend (Jaeger, Grafana Tempo, Datadog, etc.).
//!
//! Gated behind the `otel` feature flag.
//!
//! This is the bridge between ZeroPoint's verifiability model and the
//! observability ecosystem. Developer tool users get receipts in their
//! dashboards; protocol users get a standard way to query trust posture.

use crate::Receipt;
use opentelemetry::trace::{SpanKind, StatusCode};
use opentelemetry::{Key, KeyValue, Value};

/// Trait for exporting receipts as OTEL spans.
pub trait ReceiptSpanExporter {
    /// Convert a receipt into OTEL span attributes.
    fn to_span_attributes(&self) -> Vec<KeyValue>;

    /// Get the OTEL span name for this receipt.
    fn span_name(&self) -> String;

    /// Get the OTEL span kind.
    fn span_kind(&self) -> SpanKind;

    /// Get the OTEL status code.
    fn span_status(&self) -> StatusCode;
}

impl ReceiptSpanExporter for Receipt {
    fn to_span_attributes(&self) -> Vec<KeyValue> {
        let mut attrs = vec![
            KeyValue::new("zp.receipt.id", self.id.clone()),
            KeyValue::new("zp.receipt.version", self.version.clone()),
            KeyValue::new("zp.receipt.type", self.receipt_type.to_string()),
            KeyValue::new("zp.receipt.status", format!("{:?}", self.status)),
            KeyValue::new("zp.receipt.content_hash", self.content_hash.clone()),
            KeyValue::new("zp.receipt.trust_grade", format!("{:?}", self.trust_grade)),
        ];

        if let Some(ref parent) = self.parent_receipt_id {
            attrs.push(KeyValue::new("zp.receipt.parent_id", parent.clone()));
        }

        if let Some(ref sig) = self.signature {
            attrs.push(KeyValue::new("zp.receipt.signed", true));
        } else {
            attrs.push(KeyValue::new("zp.receipt.signed", false));
        }

        if let Some(ref executor) = self.executor {
            attrs.push(KeyValue::new("zp.executor.id", executor.id.clone()));
            if let Some(ref rt) = executor.runtime {
                attrs.push(KeyValue::new("zp.executor.runtime", rt.clone()));
            }
            if let Some(ref fw) = executor.framework {
                attrs.push(KeyValue::new("zp.executor.framework", fw.clone()));
            }
        }

        if let Some(ref action) = self.action {
            attrs.push(KeyValue::new(
                "zp.action.type",
                format!("{:?}", action.action_type),
            ));
            if let Some(ref name) = action.name {
                attrs.push(KeyValue::new("zp.action.name", name.clone()));
            }
            if let Some(exit_code) = action.exit_code {
                attrs.push(KeyValue::new("zp.action.exit_code", exit_code as i64));
            }
        }

        if let Some(ref timing) = self.timing {
            attrs.push(KeyValue::new(
                "zp.timing.duration_ms",
                timing.duration_ms as i64,
            ));
        }

        if let Some(ref resources) = self.resources {
            if let Some(cpu) = resources.cpu_seconds {
                attrs.push(KeyValue::new("zp.resources.cpu_seconds", cpu));
            }
            if let Some(mem) = resources.memory_peak_bytes {
                attrs.push(KeyValue::new("zp.resources.memory_peak_bytes", mem as i64));
            }
            if let Some(tokens_in) = resources.tokens_input {
                attrs.push(KeyValue::new("zp.resources.tokens_input", tokens_in as i64));
            }
            if let Some(tokens_out) = resources.tokens_output {
                attrs.push(KeyValue::new(
                    "zp.resources.tokens_output",
                    tokens_out as i64,
                ));
            }
            if let Some(cost) = resources.cost_usd {
                attrs.push(KeyValue::new("zp.resources.cost_usd", cost));
            }
        }

        if let Some(ref policy) = self.policy {
            attrs.push(KeyValue::new(
                "zp.policy.decision",
                format!("{:?}", policy.decision),
            ));
            if let Some(ref tier) = policy.trust_tier {
                attrs.push(KeyValue::new("zp.policy.trust_tier", format!("{:?}", tier)));
            }
        }

        if let Some(ref chain) = self.chain {
            if let Some(seq) = chain.sequence {
                attrs.push(KeyValue::new("zp.chain.sequence", seq as i64));
            }
            if let Some(ref chain_id) = chain.chain_id {
                attrs.push(KeyValue::new("zp.chain.id", chain_id.clone()));
            }
        }

        attrs
    }

    fn span_name(&self) -> String {
        match &self.action {
            Some(action) => {
                let name = action.name.as_deref().unwrap_or("unknown");
                format!("zp.{}.{}", self.receipt_type, name)
            }
            None => format!("zp.{}", self.receipt_type),
        }
    }

    fn span_kind(&self) -> SpanKind {
        match self.receipt_type {
            crate::ReceiptType::Execution => SpanKind::Internal,
            crate::ReceiptType::Payment => SpanKind::Client,
            crate::ReceiptType::Access => SpanKind::Client,
            crate::ReceiptType::Approval => SpanKind::Internal,
            _ => SpanKind::Internal,
        }
    }

    fn span_status(&self) -> StatusCode {
        match self.status {
            crate::Status::Success | crate::Status::Partial => StatusCode::Ok,
            crate::Status::Pending => StatusCode::Unset,
            _ => StatusCode::Error,
        }
    }
}

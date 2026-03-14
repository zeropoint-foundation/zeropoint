//! Mock healthcare data models for the Trust Triangle demo.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Clinic Data ──────────────────────────────────────────────────

/// A patient appointment record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatientAppointment {
    pub patient_id: String,
    pub patient_name: String,
    pub condition: String,
    pub scheduled_date: String,
    pub previous_date: Option<String>,
    pub status: String,
}

/// Mock clinic database with appointment records.
pub struct ClinicDb {
    appointments: HashMap<String, PatientAppointment>,
}

impl Default for ClinicDb {
    fn default() -> Self {
        Self::new()
    }
}

impl ClinicDb {
    /// Create the mock database with sample data.
    pub fn new() -> Self {
        let mut appointments = HashMap::new();

        // Our patient — appointment was rescheduled
        appointments.insert(
            "patient-12345".into(),
            PatientAppointment {
                patient_id: "patient-12345".into(),
                patient_name: "Alex Chen".into(),
                condition: "hypertension follow-up".into(),
                scheduled_date: "2026-03-08".into(),
                previous_date: Some("2026-03-01".into()),
                status: "rescheduled".into(),
            },
        );

        // Other patients (will be redacted for foreign queries)
        for (id, name, status) in [
            ("patient-00001", "Jordan Lee", "scheduled"),
            ("patient-00002", "Morgan Davis", "completed"),
            ("patient-00003", "Riley Taylor", "scheduled"),
            ("patient-00004", "Casey Wilson", "cancelled"),
        ] {
            appointments.insert(
                id.into(),
                PatientAppointment {
                    patient_id: id.into(),
                    patient_name: name.into(),
                    condition: "routine checkup".into(),
                    scheduled_date: "2026-03-10".into(),
                    previous_date: None,
                    status: status.into(),
                },
            );
        }

        Self { appointments }
    }

    /// Query for a specific patient. Returns the record and the total
    /// number of other records that were NOT returned (redacted).
    pub fn query_patient(&self, patient_id: &str) -> (Option<PatientAppointment>, usize) {
        let record = self.appointments.get(patient_id).cloned();
        let redacted_count = if record.is_some() {
            self.appointments.len() - 1
        } else {
            self.appointments.len()
        };
        (record, redacted_count)
    }
}

// ── Pharmacy Data ────────────────────────────────────────────────

/// A prescription record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrescriptionRecord {
    pub patient_id: String,
    pub medication: String,
    pub dosage: String,
    pub filled_date: String,
    pub pickup_date: Option<String>,
    pub status: String,
    pub ready_since: Option<String>,
}

/// Mock pharmacy database with prescription records.
pub struct PharmacyDb {
    prescriptions: Vec<PrescriptionRecord>,
}

impl Default for PharmacyDb {
    fn default() -> Self {
        Self::new()
    }
}

impl PharmacyDb {
    /// Create the mock database with sample data.
    pub fn new() -> Self {
        let prescriptions = vec![
            // Our patient — prescription filled, ready for pickup
            PrescriptionRecord {
                patient_id: "patient-12345".into(),
                medication: "Lisinopril".into(),
                dosage: "10mg".into(),
                filled_date: "2026-03-04".into(),
                pickup_date: None,
                status: "ready_for_pickup".into(),
                ready_since: Some("2026-03-05T14:00:00Z".into()),
            },
            // Other patients
            PrescriptionRecord {
                patient_id: "patient-00001".into(),
                medication: "Metformin".into(),
                dosage: "500mg".into(),
                filled_date: "2026-03-03".into(),
                pickup_date: Some("2026-03-03".into()),
                status: "picked_up".into(),
                ready_since: None,
            },
            PrescriptionRecord {
                patient_id: "patient-00002".into(),
                medication: "Omeprazole".into(),
                dosage: "20mg".into(),
                filled_date: "2026-03-01".into(),
                pickup_date: None,
                status: "pending".into(),
                ready_since: None,
            },
        ];

        Self { prescriptions }
    }

    /// Query for a specific patient's prescriptions. Returns matching
    /// records and the count of redacted records.
    pub fn query_patient(&self, patient_id: &str) -> (Vec<PrescriptionRecord>, usize) {
        let matching: Vec<_> = self
            .prescriptions
            .iter()
            .filter(|p| p.patient_id == patient_id)
            .cloned()
            .collect();
        let redacted_count = self.prescriptions.len() - matching.len();
        (matching, redacted_count)
    }
}

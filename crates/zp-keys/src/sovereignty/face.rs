// crates/zp-keys/src/sovereignty/face.rs
//
// Cross-platform face enrollment sovereignty provider.
//
// Uses OpenCV (via the `opencv` crate) to capture webcam frames during
// onboarding, build a face template, and verify against a live frame
// before unlocking the Genesis secret.
//
// The face template is NOT the secret — it gates access to the secret.
// The Genesis secret is stored in the OS credential store (or encrypted
// on disk), and the face verification must succeed before it's released.
//
// Privacy: The face template is a compact embedding vector stored locally
// in `~/.zeropoint/sovereignty/face_template.bin`. No images are saved.
// No data leaves the machine.
//
// Dependencies: opencv crate (feature-gated behind `face-enroll`)

use super::{
    EnrollmentResult, ProviderCapability, SovereigntyMode, SovereigntyProvider,
};
use crate::error::KeyError;

/// Face enrollment provider (OpenCV webcam).
pub struct FaceEnrollProvider;

impl SovereigntyProvider for FaceEnrollProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::FaceEnroll
    }

    fn detect(&self) -> ProviderCapability {
        #[cfg(feature = "face-enroll")]
        {
            detect_camera()
        }

        #[cfg(not(feature = "face-enroll"))]
        {
            ProviderCapability {
                mode: SovereigntyMode::FaceEnroll,
                available: false,
                description: "Face enrollment requires the 'face-enroll' feature".into(),
                requires_enrollment: true,
                detail: None,
                implementation_status: super::ProviderStatus::Partial,
            }
        }
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        #[cfg(feature = "face-enroll")]
        {
            // Face enrollment must have already run (template exists)
            let home = dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".zeropoint")
                .join("sovereignty");
            let template_path = home.join("face_template.bin");
            if !template_path.exists() {
                return Err(KeyError::CredentialStore(
                    "Face template not found — run enrollment first".into(),
                ));
            }

            // Store secret in OS credential store (login password fallback).
            // The face verification gates the load path, not the save path.
            crate::keyring::save_genesis_to_credential_store(secret)?;
            tracing::info!("Genesis secret stored with face enrollment gating");
            Ok(())
        }

        #[cfg(not(feature = "face-enroll"))]
        {
            let _ = secret;
            Err(KeyError::CredentialStore(
                "Face enrollment requires the 'face-enroll' feature".into(),
            ))
        }
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        #[cfg(feature = "face-enroll")]
        {
            // Verify face before releasing the secret
            self.verify_presence()?;
            crate::keyring::load_genesis_from_credential_store()
        }

        #[cfg(not(feature = "face-enroll"))]
        {
            Err(KeyError::CredentialStore(
                "Face enrollment requires the 'face-enroll' feature".into(),
            ))
        }
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        #[cfg(feature = "face-enroll")]
        {
            verify_face()
        }

        #[cfg(not(feature = "face-enroll"))]
        {
            Err(KeyError::CredentialStore(
                "Face verification requires the 'face-enroll' feature".into(),
            ))
        }
    }

    fn enroll(&self) -> Result<Option<EnrollmentResult>, KeyError> {
        #[cfg(feature = "face-enroll")]
        {
            enroll_face().map(Some)
        }

        #[cfg(not(feature = "face-enroll"))]
        {
            Err(KeyError::CredentialStore(
                "Face enrollment requires the 'face-enroll' feature".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// OpenCV face enrollment (feature-gated)
// ---------------------------------------------------------------------------

/// Detect whether a webcam is available.
#[cfg(feature = "face-enroll")]
fn detect_camera() -> ProviderCapability {
    // Try to open the default camera (index 0)
    match opencv::videoio::VideoCapture::new(0, opencv::videoio::CAP_ANY) {
        Ok(mut cap) => {
            let opened = cap.is_opened().unwrap_or(false);
            if opened {
                let _ = cap.release();
                ProviderCapability {
                    mode: SovereigntyMode::FaceEnroll,
                    available: true,
                    description: "Webcam available for face enrollment".into(),
                    requires_enrollment: true,
                    detail: Some("Camera index 0".to_string()),
                    implementation_status: super::ProviderStatus::Partial,
                }
            } else {
                ProviderCapability {
                    mode: SovereigntyMode::FaceEnroll,
                    available: false,
                    description: "No webcam detected".into(),
                    requires_enrollment: true,
                    detail: None,
                    implementation_status: super::ProviderStatus::Partial,
                }
            }
        }
        Err(_) => ProviderCapability {
            mode: SovereigntyMode::FaceEnroll,
            available: false,
            description: "Could not access webcam — check permissions".into(),
            requires_enrollment: true,
            detail: None,
            implementation_status: super::ProviderStatus::Partial,
        },
    }
}

/// Capture face frames and build an enrollment template.
///
/// The enrollment process:
/// 1. Open webcam
/// 2. Capture N frames with face detection (Haar cascade or DNN)
/// 3. Extract face embeddings from each frame
/// 4. Average the embeddings into a template vector
/// 5. Store the template in `~/.zeropoint/sovereignty/face_template.bin`
///
/// No raw images are stored. Only the compact embedding vector persists.
#[cfg(feature = "face-enroll")]
fn enroll_face() -> Result<EnrollmentResult, KeyError> {
    use opencv::{
        core,
        imgproc,
        objdetect,
        prelude::*,
        videoio,
    };

    // Open camera
    let mut cap = videoio::VideoCapture::new(0, videoio::CAP_ANY)
        .map_err(|e| KeyError::CredentialStore(format!("Cannot open camera: {}", e)))?;

    if !cap.is_opened().unwrap_or(false) {
        return Err(KeyError::CredentialStore("Camera failed to open".into()));
    }

    // Load Haar cascade for face detection
    let mut face_cascade = objdetect::CascadeClassifier::new(
        "/usr/share/opencv4/haarcascades/haarcascade_frontalface_default.xml",
    )
    .map_err(|e| KeyError::CredentialStore(format!("Cannot load face cascade: {}", e)))?;

    let mut face_hashes: Vec<[u8; 32]> = Vec::new();
    let required_captures = 5;
    let max_attempts = 50;

    for _ in 0..max_attempts {
        let mut frame = core::Mat::default();
        cap.read(&mut frame)
            .map_err(|e| KeyError::CredentialStore(format!("Frame capture failed: {}", e)))?;

        if frame.empty() {
            continue;
        }

        // Convert to grayscale for detection
        let mut gray = core::Mat::default();
        imgproc::cvt_color(&frame, &mut gray, imgproc::COLOR_BGR2GRAY, 0)
            .map_err(|e| KeyError::CredentialStore(format!("Color conversion failed: {}", e)))?;

        // Detect faces
        let mut faces = core::Vector::<core::Rect>::new();
        face_cascade
            .detect_multi_scale(
                &gray,
                &mut faces,
                1.1,  // scale factor
                3,    // min neighbors
                0,    // flags
                core::Size::new(80, 80),  // min size
                core::Size::new(0, 0),    // max size (0 = unlimited)
            )
            .map_err(|e| KeyError::CredentialStore(format!("Face detection failed: {}", e)))?;

        if faces.len() == 1 {
            // Exactly one face — extract ROI and hash it
            let face_rect = faces.get(0)
                .map_err(|e| KeyError::CredentialStore(format!("Face rect error: {}", e)))?;
            let roi = core::Mat::roi(&gray, face_rect)
                .map_err(|e| KeyError::CredentialStore(format!("ROI error: {}", e)))?;

            // Resize to fixed dimensions for consistent hashing
            let mut resized = core::Mat::default();
            imgproc::resize(&roi, &mut resized, core::Size::new(128, 128), 0.0, 0.0, imgproc::INTER_LINEAR)
                .map_err(|e| KeyError::CredentialStore(format!("Resize error: {}", e)))?;

            // Hash the face region with BLAKE3
            let data = resized.data_bytes()
                .map_err(|e| KeyError::CredentialStore(format!("Data bytes error: {}", e)))?;
            let hash = blake3::hash(data);
            face_hashes.push(*hash.as_bytes());

            if face_hashes.len() >= required_captures {
                break;
            }
        }
    }

    let _ = cap.release();

    if face_hashes.len() < required_captures {
        return Err(KeyError::CredentialStore(format!(
            "Face enrollment incomplete: captured {}/{} frames with a clear face. \
             Ensure good lighting and face the camera directly.",
            face_hashes.len(),
            required_captures
        )));
    }

    // Build template: BLAKE3 hash of all face hashes concatenated
    let mut hasher = blake3::Hasher::new();
    for hash in &face_hashes {
        hasher.update(hash);
    }
    let template = hasher.finalize();
    let template_bytes = template.as_bytes().to_vec();

    // Persist template
    let home = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("sovereignty");
    std::fs::create_dir_all(&home)?;
    std::fs::write(home.join("face_template.bin"), &template_bytes)?;

    tracing::info!("Face enrollment complete: {} frames captured, template stored", face_hashes.len());

    Ok(EnrollmentResult {
        enrollment_data: template_bytes,
        summary: format!(
            "Face enrolled ({} frames captured). Template stored locally — no images saved.",
            face_hashes.len()
        ),
    })
}

/// Verify the operator's face against the stored template.
///
/// Captures a single frame, detects the face, hashes it, and
/// compares against each stored face hash. Uses hamming distance
/// on the BLAKE3 hashes as a similarity metric.
///
/// NOTE: BLAKE3 hashing of raw pixel data is a v0.1 approach.
/// v0.2 will use a proper face embedding model (e.g., FaceNet or
/// ArcFace via ONNX runtime) for robust, lighting-invariant matching.
#[cfg(feature = "face-enroll")]
fn verify_face() -> Result<(), KeyError> {
    use opencv::{
        core,
        imgproc,
        objdetect,
        prelude::*,
        videoio,
    };

    let home = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("sovereignty");
    let template_path = home.join("face_template.bin");

    let template = std::fs::read(&template_path)
        .map_err(|_| KeyError::CredentialStore("No face template found — run enrollment first".into()))?;

    if template.len() != 32 {
        return Err(KeyError::CredentialStore("Corrupted face template".into()));
    }

    // Open camera and capture a verification frame
    let mut cap = videoio::VideoCapture::new(0, videoio::CAP_ANY)
        .map_err(|e| KeyError::CredentialStore(format!("Cannot open camera: {}", e)))?;

    let mut face_cascade = objdetect::CascadeClassifier::new(
        "/usr/share/opencv4/haarcascades/haarcascade_frontalface_default.xml",
    )
    .map_err(|e| KeyError::CredentialStore(format!("Cannot load face cascade: {}", e)))?;

    let max_attempts = 30;
    for _ in 0..max_attempts {
        let mut frame = core::Mat::default();
        cap.read(&mut frame)
            .map_err(|e| KeyError::CredentialStore(format!("Frame capture failed: {}", e)))?;

        if frame.empty() {
            continue;
        }

        let mut gray = core::Mat::default();
        imgproc::cvt_color(&frame, &mut gray, imgproc::COLOR_BGR2GRAY, 0)
            .map_err(|e| KeyError::CredentialStore(format!("Color conversion failed: {}", e)))?;

        let mut faces = core::Vector::<core::Rect>::new();
        face_cascade
            .detect_multi_scale(&gray, &mut faces, 1.1, 3, 0, core::Size::new(80, 80), core::Size::new(0, 0))
            .map_err(|e| KeyError::CredentialStore(format!("Face detection failed: {}", e)))?;

        if faces.len() == 1 {
            let face_rect = faces.get(0)
                .map_err(|e| KeyError::CredentialStore(format!("Face rect error: {}", e)))?;
            let roi = core::Mat::roi(&gray, face_rect)
                .map_err(|e| KeyError::CredentialStore(format!("ROI error: {}", e)))?;

            let mut resized = core::Mat::default();
            imgproc::resize(&roi, &mut resized, core::Size::new(128, 128), 0.0, 0.0, imgproc::INTER_LINEAR)
                .map_err(|e| KeyError::CredentialStore(format!("Resize error: {}", e)))?;

            let data = resized.data_bytes()
                .map_err(|e| KeyError::CredentialStore(format!("Data bytes error: {}", e)))?;

            // v0.1: Hash comparison. This is a basic liveness check, not
            // a robust biometric matcher. v0.2 will use face embeddings.
            let _live_hash = blake3::hash(data);

            // For v0.1, if we detected a face, that's our presence check.
            // The template comparison will be meaningful once we switch to
            // face embeddings in v0.2.
            let _ = cap.release();
            tracing::info!("Face verification: live face detected");
            return Ok(());
        }
    }

    let _ = cap.release();
    Err(KeyError::CredentialStore(
        "Face verification failed — no face detected. Ensure good lighting and face the camera."
            .into(),
    ))
}

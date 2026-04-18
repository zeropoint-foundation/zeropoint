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
// Privacy: The face template is stored locally in
// `~/.zeropoint/sovereignty/face_template.bin`. No images are saved.
// No data leaves the machine.
//
// v0.1 (face-enroll feature only):
//   - Face detection via Haar cascade
//   - Template is BLAKE3 hash of 128x128 pixel data
//   - Verify = "a face was detected" (presence, not identity)
//
// v0.2 (face-embeddings feature):
//   - Face detection via Haar cascade (same)
//   - Template is a 128-d embedding vector from MobileFaceNet (ONNX)
//   - Verify = cosine similarity between live embedding and stored template
//   - Threshold: 0.55 (adjustable via ZP_FACE_THRESHOLD env var)
//   - This actually confirms the RIGHT person, not just ANY person
//
// Dependencies:
//   - opencv crate (feature-gated behind `face-enroll`)
//   - tract-onnx + ndarray (feature-gated behind `face-embeddings`)

use super::{EnrollmentResult, ProviderCapability, SovereigntyMode, SovereigntyProvider};
use crate::error::KeyError;

/// Face enrollment provider (OpenCV webcam).
pub struct FaceEnrollProvider;

/// Cosine similarity threshold for face verification.
/// Pairs of the same person typically score > 0.6.
/// Different people typically score < 0.4.
/// 0.55 provides a reasonable balance with low false-accept rate.
#[cfg(feature = "face-embeddings")]
const DEFAULT_FACE_THRESHOLD: f32 = 0.55;

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
                implementation_status: if cfg!(feature = "face-embeddings") {
                    super::ProviderStatus::Ready
                } else {
                    super::ProviderStatus::Partial
                },
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

    fn capabilities(&self) -> super::ProviderCapabilities {
        use super::ProviderCapabilities;
        let mut caps = ProviderCapabilities::BASE.union(ProviderCapabilities::CAN_UPGRADE);
        if cfg!(feature = "face-embeddings") {
            caps = caps.union(ProviderCapabilities::HAS_BIOMETRIC_EVIDENCE);
        }
        caps
    }

    fn biometric_evidence(&self) -> Option<super::touchid::BiometricEvidence> {
        #[cfg(feature = "face-embeddings")]
        {
            use rand::RngCore;
            let mut nonce_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
            let nonce_hex = hex::encode(nonce_bytes);
            let timestamp = chrono::Utc::now().to_rfc3339();

            let mut hasher = blake3::Hasher::new();
            hasher.update(nonce_bytes.as_ref());
            hasher.update(b"face_verified");
            hasher.update(timestamp.as_bytes());
            let response = hasher.finalize().to_hex().to_string();

            Some(super::touchid::BiometricEvidence {
                method: "face_embedding".to_string(),
                verified_at: timestamp,
                challenge_nonce: nonce_hex,
                challenge_response: response,
                os_enforced: false, // face is always application-layer
                hardware_attestation: String::new(),
            })
        }

        #[cfg(not(feature = "face-embeddings"))]
        {
            None
        }
    }

    fn upgrade_from(
        &self,
        secret: &[u8; 32],
    ) -> Result<Option<super::EnrollmentResult>, KeyError> {
        // Enroll face, then save the secret under face gating
        let enrollment = self.enroll()?;
        self.save_secret(secret)?;
        Ok(enrollment)
    }
}

// ---------------------------------------------------------------------------
// OpenCV face detection (shared by v0.1 and v0.2)
// ---------------------------------------------------------------------------

/// Detect whether a webcam is available.
#[cfg(feature = "face-enroll")]
fn detect_camera() -> ProviderCapability {
    match opencv::videoio::VideoCapture::new(0, opencv::videoio::CAP_ANY) {
        Ok(mut cap) => {
            let opened = cap.is_opened().unwrap_or(false);
            if opened {
                let _ = cap.release();
                let status = if cfg!(feature = "face-embeddings") {
                    super::ProviderStatus::Ready
                } else {
                    super::ProviderStatus::Partial
                };
                ProviderCapability {
                    mode: SovereigntyMode::FaceEnroll,
                    available: true,
                    description: if cfg!(feature = "face-embeddings") {
                        "Webcam available — face embedding verification (v0.2)".into()
                    } else {
                        "Webcam available — face presence detection (v0.1)".into()
                    },
                    requires_enrollment: true,
                    detail: Some("Camera index 0".to_string()),
                    implementation_status: status,
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

/// Capture a face ROI from a single frame using Haar cascade.
/// Returns the 128x128 grayscale face region as raw bytes.
#[cfg(feature = "face-enroll")]
fn capture_face_roi(
    cap: &mut opencv::videoio::VideoCapture,
    face_cascade: &mut opencv::objdetect::CascadeClassifier,
) -> Result<Option<Vec<u8>>, KeyError> {
    use opencv::{core, imgproc, prelude::*};

    let mut frame = core::Mat::default();
    cap.read(&mut frame)
        .map_err(|e| KeyError::CredentialStore(format!("Frame capture failed: {}", e)))?;

    if frame.empty() {
        return Ok(None);
    }

    let mut gray = core::Mat::default();
    imgproc::cvt_color(&frame, &mut gray, imgproc::COLOR_BGR2GRAY, 0)
        .map_err(|e| KeyError::CredentialStore(format!("Color conversion failed: {}", e)))?;

    let mut faces = core::Vector::<core::Rect>::new();
    face_cascade
        .detect_multi_scale(
            &gray,
            &mut faces,
            1.1,
            3,
            0,
            core::Size::new(80, 80),
            core::Size::new(0, 0),
        )
        .map_err(|e| KeyError::CredentialStore(format!("Face detection failed: {}", e)))?;

    if faces.len() != 1 {
        return Ok(None); // Need exactly one face
    }

    let face_rect = faces
        .get(0)
        .map_err(|e| KeyError::CredentialStore(format!("Face rect error: {}", e)))?;
    let roi = core::Mat::roi(&gray, face_rect)
        .map_err(|e| KeyError::CredentialStore(format!("ROI error: {}", e)))?;

    let mut resized = core::Mat::default();
    imgproc::resize(
        &roi,
        &mut resized,
        core::Size::new(128, 128),
        0.0,
        0.0,
        imgproc::INTER_LINEAR,
    )
    .map_err(|e| KeyError::CredentialStore(format!("Resize error: {}", e)))?;

    let data = resized
        .data_bytes()
        .map_err(|e| KeyError::CredentialStore(format!("Data bytes error: {}", e)))?;

    Ok(Some(data.to_vec()))
}

// ===========================================================================
// v0.2: Face embedding enrollment + verification (face-embeddings feature)
// ===========================================================================

#[cfg(feature = "face-embeddings")]
mod embeddings {
    use crate::error::KeyError;

    /// Path to the MobileFaceNet ONNX model.
    /// The model is expected at ~/.zeropoint/models/mobilefacenet.onnx
    /// It can be downloaded during onboarding or bundled with the binary.
    fn model_path() -> std::path::PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zeropoint")
            .join("models")
            .join("mobilefacenet.onnx")
    }

    /// Compute a 128-d face embedding from a 128x128 grayscale face ROI.
    ///
    /// The MobileFaceNet model expects a 112x112 RGB input. We:
    /// 1. Resize 128x128 gray → 112x112
    /// 2. Convert grayscale to 3-channel (repeat)
    /// 3. Normalize to [-1, 1]
    /// 4. Run inference via tract
    /// 5. L2-normalize the output embedding
    pub fn compute_embedding(face_roi_128: &[u8]) -> Result<Vec<f32>, KeyError> {
        use ndarray::Array4;
        use tract_onnx::prelude::*;

        let model_file = model_path();
        if !model_file.exists() {
            return Err(KeyError::CredentialStore(format!(
                "Face embedding model not found at {}. \
                 Download MobileFaceNet ONNX model to this path.",
                model_file.display()
            )));
        }

        // Load and optimize the model
        let model = tract_onnx::onnx()
            .model_for_path(&model_file)
            .map_err(|e| KeyError::CredentialStore(format!("Model load error: {}", e)))?
            .with_input_fact(
                0,
                InferenceFact::dt_shape(f32::datum_type(), tvec![1, 3, 112, 112]),
            )
            .map_err(|e| KeyError::CredentialStore(format!("Model input error: {}", e)))?
            .into_optimized()
            .map_err(|e| KeyError::CredentialStore(format!("Model optimization error: {}", e)))?
            .into_runnable()
            .map_err(|e| KeyError::CredentialStore(format!("Model runnable error: {}", e)))?;

        // Prepare input: 128x128 gray → 112x112, normalize, expand to 3 channels
        // Simple nearest-neighbor downscale from 128 to 112
        let mut input = Array4::<f32>::zeros((1, 3, 112, 112));
        for y in 0..112 {
            for x in 0..112 {
                let src_y = (y * 128) / 112;
                let src_x = (x * 128) / 112;
                let idx = src_y * 128 + src_x;
                let pixel = if idx < face_roi_128.len() {
                    face_roi_128[idx] as f32 / 127.5 - 1.0 // normalize to [-1, 1]
                } else {
                    0.0
                };
                // Replicate grayscale across RGB channels
                input[[0, 0, y, x]] = pixel;
                input[[0, 1, y, x]] = pixel;
                input[[0, 2, y, x]] = pixel;
            }
        }

        let input_tensor: Tensor = input.into();
        let result = model
            .run(tvec![input_tensor.into()])
            .map_err(|e| KeyError::CredentialStore(format!("Inference error: {}", e)))?;

        let output = result[0]
            .to_array_view::<f32>()
            .map_err(|e| KeyError::CredentialStore(format!("Output conversion error: {}", e)))?;

        let embedding: Vec<f32> = output.iter().copied().collect();

        // L2 normalize
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm < 1e-10 {
            return Err(KeyError::CredentialStore(
                "Face embedding has zero norm — model may have failed".into(),
            ));
        }
        let normalized: Vec<f32> = embedding.iter().map(|x| x / norm).collect();

        Ok(normalized)
    }

    /// Cosine similarity between two L2-normalized embedding vectors.
    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }
        a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
    }

    /// Serialize an embedding vector to bytes for storage.
    pub fn embedding_to_bytes(embedding: &[f32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + embedding.len() * 4);
        // Header: version byte + dimension count
        bytes.push(2); // v0.2 format
        bytes.extend_from_slice(&(embedding.len() as u16).to_le_bytes());
        bytes.push(0); // padding
        for val in embedding {
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        bytes
    }

    /// Deserialize an embedding vector from stored bytes.
    pub fn embedding_from_bytes(bytes: &[u8]) -> Result<Vec<f32>, KeyError> {
        if bytes.len() < 4 {
            return Err(KeyError::CredentialStore(
                "Corrupted face template (too short)".into(),
            ));
        }

        let version = bytes[0];
        if version == 2 {
            // v0.2 embedding format
            let dim = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
            let expected_len = 4 + dim * 4;
            if bytes.len() < expected_len {
                return Err(KeyError::CredentialStore(format!(
                    "Corrupted face template: expected {} bytes, got {}",
                    expected_len,
                    bytes.len()
                )));
            }
            let mut embedding = Vec::with_capacity(dim);
            for i in 0..dim {
                let offset = 4 + i * 4;
                let val = f32::from_le_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]);
                embedding.push(val);
            }
            Ok(embedding)
        } else if bytes.len() == 32 {
            // v0.1 BLAKE3 hash format — cannot do embedding comparison
            Err(KeyError::CredentialStore(
                "Face template is v0.1 format (BLAKE3 hash). \
                 Re-enroll with `zp sovereignty-upgrade face_enroll` \
                 to use v0.2 embedding-based verification."
                    .into(),
            ))
        } else {
            Err(KeyError::CredentialStore(
                "Unknown face template format".into(),
            ))
        }
    }
}

// ===========================================================================
// Enrollment (works for both v0.1 and v0.2)
// ===========================================================================

#[cfg(feature = "face-enroll")]
fn enroll_face() -> Result<EnrollmentResult, KeyError> {
    use opencv::{objdetect, prelude::*, videoio};

    let mut cap = videoio::VideoCapture::new(0, videoio::CAP_ANY)
        .map_err(|e| KeyError::CredentialStore(format!("Cannot open camera: {}", e)))?;

    if !cap.is_opened().unwrap_or(false) {
        return Err(KeyError::CredentialStore("Camera failed to open".into()));
    }

    let mut face_cascade = objdetect::CascadeClassifier::new(
        "/usr/share/opencv4/haarcascades/haarcascade_frontalface_default.xml",
    )
    .map_err(|e| KeyError::CredentialStore(format!("Cannot load face cascade: {}", e)))?;

    let required_captures = 5;
    let max_attempts = 50;
    let mut face_rois: Vec<Vec<u8>> = Vec::new();

    for _ in 0..max_attempts {
        match capture_face_roi(&mut cap, &mut face_cascade)? {
            Some(roi_data) => {
                face_rois.push(roi_data);
                if face_rois.len() >= required_captures {
                    break;
                }
            }
            None => continue,
        }
    }

    let _ = cap.release();

    if face_rois.len() < required_captures {
        return Err(KeyError::CredentialStore(format!(
            "Face enrollment incomplete: captured {}/{} frames with a clear face. \
             Ensure good lighting and face the camera directly.",
            face_rois.len(),
            required_captures
        )));
    }

    // Build template based on available features
    let (template_bytes, summary) = build_face_template(&face_rois)?;

    // Persist template
    let home = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("sovereignty");
    std::fs::create_dir_all(&home)?;
    std::fs::write(home.join("face_template.bin"), &template_bytes)?;

    tracing::info!("{}", summary);

    Ok(EnrollmentResult {
        enrollment_data: template_bytes,
        summary,
    })
}

/// Build the face template from captured ROIs.
///
/// v0.2 (face-embeddings): Computes embedding for each frame, averages them,
/// L2-normalizes the result. This produces a robust template that's
/// invariant to minor lighting/angle changes.
///
/// v0.1 (face-enroll only): BLAKE3 hash of concatenated pixel hashes.
/// This is a presence check, not identity verification.
#[cfg(feature = "face-enroll")]
fn build_face_template(face_rois: &[Vec<u8>]) -> Result<(Vec<u8>, String), KeyError> {
    #[cfg(feature = "face-embeddings")]
    {
        // v0.2: Compute embeddings for each captured frame
        let mut all_embeddings: Vec<Vec<f32>> = Vec::new();

        for (i, roi) in face_rois.iter().enumerate() {
            match embeddings::compute_embedding(roi) {
                Ok(emb) => {
                    tracing::debug!("Frame {} embedding: {} dimensions", i, emb.len());
                    all_embeddings.push(emb);
                }
                Err(e) => {
                    tracing::warn!("Frame {} embedding failed: {} — skipping", i, e);
                }
            }
        }

        if all_embeddings.len() < 3 {
            return Err(KeyError::CredentialStore(format!(
                "Only {}/{} face frames produced valid embeddings. \
                 Check the model file and lighting conditions.",
                all_embeddings.len(),
                face_rois.len()
            )));
        }

        // Average all embeddings
        let dim = all_embeddings[0].len();
        let mut avg = vec![0.0f32; dim];
        for emb in &all_embeddings {
            for (i, val) in emb.iter().enumerate() {
                if i < dim {
                    avg[i] += val;
                }
            }
        }
        let count = all_embeddings.len() as f32;
        for val in avg.iter_mut() {
            *val /= count;
        }

        // L2 normalize the averaged embedding
        let norm: f32 = avg.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 1e-10 {
            for val in avg.iter_mut() {
                *val /= norm;
            }
        }

        let template_bytes = embeddings::embedding_to_bytes(&avg);
        let summary = format!(
            "Face enrolled ({} frames, {}-d embedding). \
             Cosine-similarity verification active (v0.2).",
            all_embeddings.len(),
            dim
        );

        Ok((template_bytes, summary))
    }

    #[cfg(not(feature = "face-embeddings"))]
    {
        // v0.1: BLAKE3 hash of pixel data
        let mut face_hashes: Vec<[u8; 32]> = Vec::new();
        for roi in face_rois {
            let hash = blake3::hash(roi);
            face_hashes.push(*hash.as_bytes());
        }

        let mut hasher = blake3::Hasher::new();
        for hash in &face_hashes {
            hasher.update(hash);
        }
        let template = hasher.finalize();
        let template_bytes = template.as_bytes().to_vec();

        let summary = format!(
            "Face enrolled ({} frames captured). Template stored locally — no images saved. \
             Note: v0.1 presence-only matching (upgrade to face-embeddings for identity verification).",
            face_rois.len()
        );

        Ok((template_bytes, summary))
    }
}

// ===========================================================================
// Verification
// ===========================================================================

#[cfg(feature = "face-enroll")]
fn verify_face() -> Result<(), KeyError> {
    use opencv::{objdetect, prelude::*, videoio};

    let home = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("sovereignty");
    let template_path = home.join("face_template.bin");

    let template_bytes = std::fs::read(&template_path).map_err(|_| {
        KeyError::CredentialStore("No face template found — run enrollment first".into())
    })?;

    // Open camera
    let mut cap = videoio::VideoCapture::new(0, videoio::CAP_ANY)
        .map_err(|e| KeyError::CredentialStore(format!("Cannot open camera: {}", e)))?;

    let mut face_cascade = objdetect::CascadeClassifier::new(
        "/usr/share/opencv4/haarcascades/haarcascade_frontalface_default.xml",
    )
    .map_err(|e| KeyError::CredentialStore(format!("Cannot load face cascade: {}", e)))?;

    let max_attempts = 30;

    // Route to the appropriate verification strategy
    #[cfg(feature = "face-embeddings")]
    {
        verify_face_v2(&template_bytes, &mut cap, &mut face_cascade, max_attempts)
    }

    #[cfg(not(feature = "face-embeddings"))]
    {
        verify_face_v1(&template_bytes, &mut cap, &mut face_cascade, max_attempts)
    }
}

/// v0.2: Embedding-based verification with cosine similarity.
#[cfg(feature = "face-embeddings")]
fn verify_face_v2(
    template_bytes: &[u8],
    cap: &mut opencv::videoio::VideoCapture,
    face_cascade: &mut opencv::objdetect::CascadeClassifier,
    max_attempts: usize,
) -> Result<(), KeyError> {
    let stored_embedding = embeddings::embedding_from_bytes(template_bytes)?;

    let threshold: f32 = std::env::var("ZP_FACE_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_FACE_THRESHOLD);

    for attempt in 0..max_attempts {
        match capture_face_roi(cap, face_cascade)? {
            Some(roi_data) => {
                match embeddings::compute_embedding(&roi_data) {
                    Ok(live_embedding) => {
                        let similarity =
                            embeddings::cosine_similarity(&stored_embedding, &live_embedding);
                        tracing::debug!(
                            "Face verify attempt {}: similarity = {:.4} (threshold = {:.2})",
                            attempt,
                            similarity,
                            threshold
                        );

                        if similarity >= threshold {
                            let _ = cap.release();
                            tracing::info!(
                                "Face verification succeeded: similarity {:.4} >= {:.2}",
                                similarity,
                                threshold
                            );
                            return Ok(());
                        }
                        // Below threshold — keep trying (lighting may improve)
                    }
                    Err(e) => {
                        tracing::debug!("Embedding computation failed on attempt {}: {}", attempt, e);
                    }
                }
            }
            None => continue, // No face detected this frame
        }
    }

    let _ = cap.release();
    Err(KeyError::CredentialStore(
        "Face verification failed — face did not match enrolled template. \
         Ensure good lighting and face the camera directly. If your appearance \
         has changed significantly, re-enroll with `zp sovereignty-upgrade face_enroll`."
            .into(),
    ))
}

/// v0.1: Presence-only verification (any face passes).
#[cfg(all(feature = "face-enroll", not(feature = "face-embeddings")))]
fn verify_face_v1(
    template_bytes: &[u8],
    cap: &mut opencv::videoio::VideoCapture,
    face_cascade: &mut opencv::objdetect::CascadeClassifier,
    max_attempts: usize,
) -> Result<(), KeyError> {
    if template_bytes.len() != 32 {
        return Err(KeyError::CredentialStore("Corrupted face template".into()));
    }

    for _ in 0..max_attempts {
        if let Some(_roi_data) = capture_face_roi(cap, face_cascade)? {
            // v0.1: face detected = presence confirmed
            let _ = cap.release();
            tracing::info!("Face verification: live face detected (v0.1 presence check)");
            return Ok(());
        }
    }

    let _ = cap.release();
    Err(KeyError::CredentialStore(
        "Face verification failed — no face detected. Ensure good lighting and face the camera."
            .into(),
    ))
}

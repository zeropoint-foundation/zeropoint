//! Calendar-server client.
//!
//! # Every protocol constant in this crate is in this file, with its status
//!
//! The OpenTimestamps calendar wire protocol could not be confirmed from a
//! written primary source on 2026-08-14: the server repository's README
//! documents only client invocations (`ots stamp -c <url>`), the calendar
//! homepages publish operational statistics and no API reference, and no
//! protocol specification was located. The constants were therefore first
//! written from prior knowledge and then checked against a live calendar.
//!
//! They are gathered here so the unverified surface stays one small file rather
//! than a risk spread through the crate. **Each carries its own status. Do not
//! let these go stale — a constant marked confirmed that nobody re-checked is
//! worse than one marked unverified.**
//!
//! ## Confirmed 2026-08-14 against `alice.btc.calendar.opentimestamps.org`
//!
//! `SUBMIT_PATH` and `ACCEPT`, together, by observation:
//!
//! ```text
//! head -c 32 /dev/zero > /tmp/d.bin
//! curl -sS -X POST --data-binary @/tmp/d.bin \
//!   -H 'Accept: application/vnd.opentimestamps.v1' \
//!   -o /tmp/ots.bin -w 'HTTP %{http_code}  %{size_download} bytes\n' \
//!   https://alice.btc.calendar.opentimestamps.org/digest
//! ```
//!
//! → `HTTP 200  172 bytes`, body beginning `f0 08 6d 76 21 db 5a b1 …` with a
//! further `f0 10` inside it. Structured binary in a tag-length-value shape,
//! not an error page. A POST of 32 raw bytes to `/digest` with that `Accept`
//! header is accepted and answered with a partial proof.
//!
//! ## Still unverified: `UPGRADE_PATH`
//!
//! Submission does not exercise it, so the check above says nothing about it.
//! To confirm, request a digest that is already attested — an all-zero digest
//! is a common enough test input that it is likely to have been stamped and
//! confirmed long ago:
//!
//! ```text
//! curl -sS -o /tmp/up.bin -w 'HTTP %{http_code}  %{size_download} bytes\n' \
//!   https://alice.btc.calendar.opentimestamps.org/timestamp/$(printf '00%.0s' {1..32})
//! ```
//!
//! A 200 with a body confirms the path. A 404 is **ambiguous** — it means
//! either "path wrong" or "this digest genuinely has no attestation yet", and
//! the two are indistinguishable by status alone. If it 404s, the honest read
//! is that the constant remains unverified, and the way to settle it is to
//! upgrade a digest this crate submitted once Bitcoin has confirmed it.
//!
//! `CALENDARS` are confirmed from the project's own uptime monitor.

use std::time::Duration;

use zp_anchor::{AnchorError, Result};

/// Public calendar servers.
///
/// **Confirmed** 2026-08-14 against the OpenTimestamps uptime monitor at
/// <https://uptime.opentimestamps.net/>, which tracks exactly these three.
/// Two are operated by the OpenTimestamps project and one by Eternity Wall —
/// deliberately not all the same operator, since the point of submitting to
/// several is that no single one can stall a commitment.
pub const CALENDARS: &[&str] = &[
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
];

/// **Confirmed 2026-08-14** — see module docs for the observation.
/// Digest submission endpoint.
const SUBMIT_PATH: &str = "/digest";

/// **UNVERIFIED** — see module docs. Completed-timestamp retrieval, suffixed
/// with the hex commitment. Submission does not exercise this path, so the
/// 2026-08-14 check confirmed the other two constants and not this one.
const UPGRADE_PATH: &str = "/timestamp/";

/// **Confirmed 2026-08-14** — see module docs. Protocol version header.
const ACCEPT: &str = "application/vnd.opentimestamps.v1";

/// A calendar's response to one submission: the opaque partial-proof bytes.
#[derive(Debug, Clone)]
pub struct PartialProof {
    pub calendar: String,
    pub bytes: Vec<u8>,
}

/// Submit a 32-byte digest to one calendar.
///
/// The digest is sent as a raw body, not hex and not JSON. Calendars treat it
/// opaquely — they commit to the bytes given and have no notion of what was
/// hashed, which is why the substrate can submit a BLAKE3 chain head where the
/// reference client would submit a SHA-256 file hash.
pub async fn submit(
    client: &reqwest::Client,
    calendar: &str,
    digest: &[u8; 32],
    timeout: Duration,
) -> Result<PartialProof> {
    let url = format!("{}{}", calendar.trim_end_matches('/'), SUBMIT_PATH);

    let resp = client
        .post(&url)
        .header(reqwest::header::ACCEPT, ACCEPT)
        .body(digest.to_vec())
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| AnchorError::Network(format!("{calendar}: submit failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(AnchorError::Rejected {
            reason: format!("{calendar}: submit returned HTTP {}", resp.status()),
        });
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AnchorError::Network(format!("{calendar}: reading proof body: {e}")))?
        .to_vec();

    if bytes.is_empty() {
        return Err(AnchorError::Rejected {
            reason: format!("{calendar}: accepted the digest but returned an empty proof"),
        });
    }

    Ok(PartialProof {
        calendar: calendar.to_string(),
        bytes,
    })
}

/// Ask a calendar for the completed, Bitcoin-attested timestamp for a digest.
///
/// `Ok(None)` means the calendar answered and does not yet have a completed
/// attestation — the ordinary state for the first hour or several after
/// submission, and not an error. `Err` means the calendar could not be reached
/// or refused.
pub async fn upgrade(
    client: &reqwest::Client,
    calendar: &str,
    digest: &[u8; 32],
    timeout: Duration,
) -> Result<Option<Vec<u8>>> {
    let url = format!(
        "{}{}{}",
        calendar.trim_end_matches('/'),
        UPGRADE_PATH,
        hex::encode(digest)
    );

    let resp = client
        .get(&url)
        .header(reqwest::header::ACCEPT, ACCEPT)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| AnchorError::Network(format!("{calendar}: upgrade failed: {e}")))?;

    // Not-yet-attested is the common case, not a fault.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(AnchorError::Network(format!(
            "{calendar}: upgrade returned HTTP {}",
            resp.status()
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AnchorError::Network(format!("{calendar}: reading upgrade body: {e}")))?
        .to_vec();

    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(bytes))
    }
}

/// Is this calendar answering at all?
pub async fn reachable(client: &reqwest::Client, calendar: &str, timeout: Duration) -> bool {
    client
        .get(calendar)
        .timeout(timeout)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The URLs are confirmed, as are `SUBMIT_PATH` and `ACCEPT` as of
    /// 2026-08-14; `UPGRADE_PATH` is not. If someone edits this list, the
    /// module docs' verification command needs re-running against whatever was
    /// added — a calendar is only as confirmed as the last check against it.
    #[test]
    fn calendars_are_distinct_operators_and_https() {
        assert_eq!(CALENDARS.len(), 3);
        for c in CALENDARS {
            assert!(c.starts_with("https://"), "{c} is not https");
            assert!(
                !c.ends_with('/'),
                "{c} has a trailing slash; submit() trims but the list should be clean"
            );
        }
        // Two opentimestamps.org, one eternitywall — plurality of operator is
        // the property, not plurality of hostname.
        let ew = CALENDARS
            .iter()
            .filter(|c| c.contains("eternitywall"))
            .count();
        assert_eq!(
            ew, 1,
            "expected exactly one non-opentimestamps.org calendar"
        );
    }

    #[test]
    fn upgrade_url_is_hex_suffixed() {
        let digest = [0xabu8; 32];
        let url = format!(
            "{}{}{}",
            CALENDARS[0].trim_end_matches('/'),
            UPGRADE_PATH,
            hex::encode(digest)
        );
        assert!(url.ends_with(&"ab".repeat(32)));
        assert!(url.contains("/timestamp/"));
    }
}

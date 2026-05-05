/**
 * DMARC report handler (dmarc@zeropoint.global).
 *
 * Trigger: DMARC aggregate reports arrive as email attachments
 * Action:
 *   1. Extract XML report from attachment (often gzip/zip compressed)
 *   2. Parse basic report metadata
 *   3. Store raw report in R2
 *   4. Record summary in D1
 */

import { ulid } from "../email/ulid.js";

/**
 * @param {Object} env
 * @param {Object} parsed    - Parsed email
 * @param {string} messageId - Stored message ID
 * @returns {Promise<{type: string, id: string}>}
 */
export async function handleDmarc(env, parsed, messageId) {
  const id = ulid();

  // DMARC reports come as XML attachments (often gzipped or zipped)
  // Store the raw report first
  let rawR2Key = null;
  let reportData = null;

  for (const att of parsed.attachments) {
    if (!att.content) continue;

    // DMARC reports are typically .xml, .xml.gz, or .zip
    const isReport =
      att.mimeType === "application/xml" ||
      att.mimeType === "text/xml" ||
      att.mimeType === "application/gzip" ||
      att.mimeType === "application/zip" ||
      (att.filename && att.filename.match(/\.(xml|xml\.gz|gz|zip)$/i));

    if (isReport) {
      rawR2Key = `dmarc/${id}/${att.filename || "report.xml"}`;
      await env.STORAGE.put(rawR2Key, att.content, {
        httpMetadata: { contentType: att.mimeType || "application/xml" },
        customMetadata: { messageId, dmarcReportId: id },
      });
      reportData = att.content;
      break; // Take first report attachment
    }
  }

  // Extract basic metadata from sender info
  // DMARC reports typically come from noreply addresses at ISPs
  const reporterOrg = extractOrgFromEmail(parsed.from);

  // Try to extract report metadata from subject
  // Common format: "Report domain: zeropoint.global Submitter: google.com Report-ID: <id>"
  const subjectMeta = parseReportSubject(parsed.subject);

  await env.DB.prepare(
    `INSERT INTO dmarc_reports (id, source_message_id, reporter_org, reporter_email, report_id, domain, raw_r2_key)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      messageId,
      reporterOrg || subjectMeta.submitter || null,
      parsed.from,
      subjectMeta.reportId || null,
      subjectMeta.domain || "zeropoint.global",
      rawR2Key
    )
    .run();

  console.log(
    JSON.stringify({
      event: "dmarc:report_stored",
      id,
      reporter: reporterOrg,
      domain: subjectMeta.domain,
      hasAttachment: !!rawR2Key,
    })
  );

  return {
    type: "dmarc",
    id,
    reporter: reporterOrg,
    domain: subjectMeta.domain || "zeropoint.global",
    hasRawReport: !!rawR2Key,
  };
}

function extractOrgFromEmail(email) {
  const domain = email.split("@")[1];
  if (!domain) return null;
  // Strip common prefixes
  return domain.replace(/^(mail\.|noreply\.|dmarc\.)/, "");
}

function parseReportSubject(subject) {
  const result = {};

  const domainMatch = subject.match(/domain:\s*([^\s]+)/i);
  if (domainMatch) result.domain = domainMatch[1];

  const submitterMatch = subject.match(/submitter:\s*([^\s]+)/i);
  if (submitterMatch) result.submitter = submitterMatch[1];

  const idMatch = subject.match(/report[- ]?id:\s*<?([^>\s]+)>?/i);
  if (idMatch) result.reportId = idMatch[1];

  return result;
}

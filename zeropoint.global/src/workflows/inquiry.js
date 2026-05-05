/**
 * Query routing workflow handler (info@zeropoint.global).
 *
 * Trigger: External email to info@zeropoint.global
 * Action:
 *   1. Classify the inquiry (grant, technical, media, partnership, general)
 *   2. Create tracked inquiry with response deadline
 *   3. Route to appropriate staff member
 */

import { ulid } from "../email/ulid.js";

/**
 * @param {Object} env
 * @param {Object} parsed    - Parsed email
 * @param {string} messageId - Stored message ID
 * @returns {Promise<{type: string, id: string}>}
 */
export async function handleInquiry(env, parsed, messageId) {
  const id = ulid();
  const category = classifyInquiry(parsed.subject, parsed.textBody || "");
  const assignedTo = routeByCategory(category);

  // Default response deadline: 2 business days
  const deadline = computeDeadline(2);

  await env.DB.prepare(
    `INSERT INTO inquiries (id, category, source_message_id, from_email, from_name, subject, summary, assigned_to, status, response_deadline)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'assigned', ?)`
  )
    .bind(
      id,
      category,
      messageId,
      parsed.from,
      parsed.fromName || null,
      parsed.subject,
      (parsed.textBody || "").slice(0, 500), // First 500 chars as summary
      assignedTo,
      deadline
    )
    .run();

  return {
    type: "inquiry",
    id,
    category,
    assignedTo,
    deadline,
    from: parsed.from,
  };
}

/**
 * Classify inquiry based on subject and body content.
 * Simple keyword matching — can be upgraded to LLM classification later.
 */
function classifyInquiry(subject, body) {
  const text = `${subject} ${body}`.toLowerCase();

  if (text.match(/grant|funding|donation|sponsor|endow/)) return "grant";
  if (text.match(/api|protocol|sdk|integration|technical|developer|code/)) return "technical";
  if (text.match(/press|media|interview|journalist|article|coverage|podcast/)) return "media";
  if (text.match(/partner|collaborat|alliance|joint|strategic/)) return "partnership";

  return "general";
}

/**
 * Route inquiry to staff based on category.
 * Ken handles grants and partnerships, Katie handles media, Lorrie handles general.
 */
function routeByCategory(category) {
  const routing = {
    grant: "ken",
    technical: "ken",
    media: "katie",
    partnership: "ken",
    general: "lorrie",
  };
  return routing[category] || "ken";
}

/**
 * Compute a deadline N business days from now.
 */
function computeDeadline(businessDays) {
  const date = new Date();
  let added = 0;
  while (added < businessDays) {
    date.setDate(date.getDate() + 1);
    const day = date.getDay();
    if (day !== 0 && day !== 6) added++;
  }
  return date.toISOString().split("T")[0];
}

/**
 * Query inquiries.
 */
export async function queryInquiries(env, opts = {}) {
  const { assignedTo, status, category, limit = 50 } = opts;

  let sql = `SELECT * FROM inquiries WHERE 1=1`;
  const params = [];

  if (assignedTo) {
    sql += ` AND assigned_to = ?`;
    params.push(assignedTo);
  }
  if (status) {
    sql += ` AND status = ?`;
    params.push(status);
  }
  if (category) {
    sql += ` AND category = ?`;
    params.push(category);
  }

  sql += ` ORDER BY created_at DESC LIMIT ?`;
  params.push(limit);

  const { results } = await env.DB.prepare(sql).bind(...params).all();
  return results;
}

/**
 * email-to-task workflow handler.
 *
 * Trigger: Send email to task@zeropoint.global
 * Subject format: [TASK] description  OR  [TASK:assignee] description
 * Action:
 *   1. Parse subject for task description and optional assignee
 *   2. Create task record in D1
 *   3. Emit task:created receipt
 */

import { ulid } from "../email/ulid.js";

/**
 * @param {Object} env
 * @param {Object} parsed    - Parsed email
 * @param {string} messageId - Stored message ID
 * @returns {Promise<{type: string, id: string}>}
 */
export async function handleTask(env, parsed, messageId) {
  const { title, assignee, priority } = parseTaskSubject(parsed.subject);

  const id = ulid();
  const now = new Date().toISOString();

  // Determine creator from sender email
  const createdBy = extractOperatorFromEmail(parsed.from) || "system";

  // Extract due date from body if present
  const dueDate = extractDueDate(parsed.textBody || "");

  await env.DB.prepare(
    `INSERT INTO tasks (id, title, description, status, priority, assignee, created_by, due_date, source_message_id, tags, created_at, updated_at)
     VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, '[]', ?, ?)`
  )
    .bind(
      id,
      title,
      parsed.textBody || parsed.htmlBody || "",
      priority,
      assignee || null,
      createdBy,
      dueDate,
      messageId,
      now,
      now
    )
    .run();

  return {
    type: "task",
    id,
    title,
    assignee: assignee || null,
    priority,
    dueDate,
  };
}

/**
 * Parse task subject line.
 *
 * Formats:
 *   [TASK] Do the thing                → { title: "Do the thing", assignee: null, priority: "normal" }
 *   [TASK:ken] Do the thing            → { title: "Do the thing", assignee: "ken", priority: "normal" }
 *   [TASK:ken:high] Do the thing       → { title: "Do the thing", assignee: "ken", priority: "high" }
 *   [URGENT] Do the thing              → { title: "Do the thing", assignee: null, priority: "urgent" }
 *   Just a plain subject               → { title: "Just a plain subject", assignee: null, priority: "normal" }
 */
function parseTaskSubject(subject) {
  // Try [TASK:assignee:priority] format
  const fullMatch = subject.match(/^\[TASK:([a-z]+):([a-z]+)\]\s*(.+)$/i);
  if (fullMatch) {
    return {
      title: fullMatch[3].trim(),
      assignee: fullMatch[1].toLowerCase(),
      priority: normalizePriority(fullMatch[2]),
    };
  }

  // Try [TASK:assignee] format
  const assigneeMatch = subject.match(/^\[TASK:([a-z]+)\]\s*(.+)$/i);
  if (assigneeMatch) {
    return {
      title: assigneeMatch[2].trim(),
      assignee: assigneeMatch[1].toLowerCase(),
      priority: "normal",
    };
  }

  // Try [TASK] format
  const taskMatch = subject.match(/^\[TASK\]\s*(.+)$/i);
  if (taskMatch) {
    return {
      title: taskMatch[1].trim(),
      assignee: null,
      priority: "normal",
    };
  }

  // Try [URGENT] format
  const urgentMatch = subject.match(/^\[URGENT\]\s*(.+)$/i);
  if (urgentMatch) {
    return {
      title: urgentMatch[1].trim(),
      assignee: null,
      priority: "urgent",
    };
  }

  // Fallback — treat entire subject as title
  return {
    title: subject.trim(),
    assignee: null,
    priority: "normal",
  };
}

function normalizePriority(p) {
  const map = { low: "low", normal: "normal", high: "high", urgent: "urgent", critical: "urgent" };
  return map[p.toLowerCase()] || "normal";
}

function extractOperatorFromEmail(email) {
  const local = email.split("@")[0].toLowerCase();
  const operators = new Set(["ken", "kalyn", "lorrie", "katie"]);
  return operators.has(local) ? local : null;
}

/**
 * Extract a due date from email body if a pattern like "by Friday" or "due: 2026-05-10" is found.
 */
function extractDueDate(text) {
  // ISO date pattern
  const isoMatch = text.match(/due[:\s]+(\d{4}-\d{2}-\d{2})/i);
  if (isoMatch) return isoMatch[1];

  // "by [day]" pattern — compute next occurrence
  const dayMatch = text.match(/by\s+(monday|tuesday|wednesday|thursday|friday|saturday|sunday)/i);
  if (dayMatch) {
    const days = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];
    const target = days.indexOf(dayMatch[1].toLowerCase());
    const today = new Date();
    const current = today.getDay();
    let daysUntil = target - current;
    if (daysUntil <= 0) daysUntil += 7;
    const due = new Date(today);
    due.setDate(due.getDate() + daysUntil);
    return due.toISOString().split("T")[0];
  }

  return null;
}

/**
 * Query tasks with filtering.
 */
export async function queryTasks(env, opts = {}) {
  const { assignee, status, limit = 50, offset = 0 } = opts;

  let sql = `SELECT * FROM tasks WHERE 1=1`;
  const params = [];

  if (assignee) {
    sql += ` AND assignee = ?`;
    params.push(assignee);
  }
  if (status) {
    sql += ` AND status = ?`;
    params.push(status);
  }

  sql += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  const { results } = await env.DB.prepare(sql).bind(...params).all();
  return results.map((r) => ({
    ...r,
    tags: JSON.parse(r.tags || "[]"),
  }));
}

/**
 * Update a task's status.
 */
export async function updateTaskStatus(env, id, status, operatorId) {
  const updates = { status, updated_at: new Date().toISOString() };
  if (status === "done") updates.completed_at = new Date().toISOString();

  const fields = Object.entries(updates)
    .map(([k]) => `${k} = ?`)
    .join(", ");

  await env.DB.prepare(
    `UPDATE tasks SET ${fields} WHERE id = ?`
  )
    .bind(...Object.values(updates), id)
    .run();
}

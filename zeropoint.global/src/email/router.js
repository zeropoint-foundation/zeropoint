/**
 * Email router — determines how to handle inbound mail
 * based on recipient address.
 *
 * Personal mailboxes get stored. Workflow addresses get dispatched.
 */

/** Known personal mailboxes */
const PERSONAL_MAILBOXES = new Set(["ken", "kalyn", "lorrie", "katie"]);

/** Workflow address handlers */
const WORKFLOW_HANDLERS = {
  publish: "publish",
  archive: "archive",
  task: "task",
  info: "route",
  dmarc: "dmarc",
};

/**
 * Resolve routing for an inbound email.
 *
 * @param {string} toAddress - Full recipient email address
 * @returns {Route}
 *
 * @typedef {Object} Route
 * @property {string} type       - 'personal' | 'workflow' | 'catchall'
 * @property {string} mailbox    - Mailbox name (e.g., 'ken', 'info')
 * @property {string} handler    - Handler name for workflow dispatch
 * @property {string} folder     - Default folder for storage
 */
export function resolveRoute(toAddress) {
  const local = toAddress.split("@")[0].toLowerCase().trim();

  // Personal mailbox
  if (PERSONAL_MAILBOXES.has(local)) {
    return {
      type: "personal",
      mailbox: local,
      handler: "store",
      folder: "inbox",
    };
  }

  // Workflow address
  if (WORKFLOW_HANDLERS[local]) {
    return {
      type: "workflow",
      mailbox: local,
      handler: WORKFLOW_HANDLERS[local],
      folder: "inbox",
    };
  }

  // Catch-all — route to Ken's inbox with a flag
  return {
    type: "catchall",
    mailbox: "ken",
    handler: "store",
    folder: "inbox",
  };
}

/**
 * Check whether the given mailbox is a personal one
 * (as opposed to a workflow/system address).
 */
export function isPersonalMailbox(mailbox) {
  return PERSONAL_MAILBOXES.has(mailbox);
}

/**
 * Return all known personal mailbox names.
 */
export function getPersonalMailboxes() {
  return [...PERSONAL_MAILBOXES];
}

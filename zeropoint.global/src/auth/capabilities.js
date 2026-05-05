/**
 * ZeroPoint capability model for the workspace.
 *
 * Each operator holds a set of capability strings.
 * Every API action requires a specific capability.
 * Capabilities are granted during onboarding via `zp` CLI
 * and stored in D1 alongside the operator's public key.
 *
 * Capability format: <domain>:<action>:<scope>
 *
 *   mail:read:ken       — read Ken's mailbox
 *   mail:read:*         — read any mailbox
 *   mail:send:ken       — send as ken@zeropoint.global
 *   mail:manage:ken     — move, star, delete in Ken's mailbox
 *   mail:admin          — manage routing rules, view all mailboxes
 *   docs:read:*         — read any document
 *   docs:write:*        — create/edit documents
 *   secure:channel:*    — access all secure channels
 *   workspace:admin     — full workspace administration
 */

/**
 * Check whether an operator's capability set satisfies a required capability.
 *
 * Supports wildcard scoping:
 *   "mail:read:*" satisfies "mail:read:ken"
 *   "workspace:admin" satisfies everything
 *
 * @param {string[]} granted   - Capabilities the operator holds
 * @param {string} required    - The capability needed for this action
 * @returns {boolean}
 */
export function hasCapability(granted, required) {
  if (!granted || !granted.length) return false;

  // workspace:admin is the root capability — grants everything
  if (granted.includes("workspace:admin")) return true;

  // Direct match
  if (granted.includes(required)) return true;

  // Wildcard match: "mail:read:*" matches "mail:read:ken"
  const requiredParts = required.split(":");
  for (const cap of granted) {
    const capParts = cap.split(":");
    if (capParts.length > requiredParts.length) continue;

    let match = true;
    for (let i = 0; i < capParts.length; i++) {
      if (capParts[i] === "*") break; // wildcard matches rest
      if (capParts[i] !== requiredParts[i]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }

  return false;
}

/**
 * Determine the capability required for a given API operation.
 *
 * @param {string} action   - Action name (e.g., "read", "send", "manage")
 * @param {string} mailbox  - Target mailbox
 * @returns {string}        - Required capability string
 */
export function mailCapability(action, mailbox) {
  return `mail:${action}:${mailbox}`;
}

/**
 * Default capability sets for each operator role.
 * Used during onboarding — can be customized per operator.
 *
 * Authority tiers:
 *   founder    — Genesis holder. Full authority.
 *   successor  — Complete succession authority. Can assume genesis.
 *   officer    — Staff with co-signed escalation path.
 */
export const DEFAULT_CAPABILITIES = {
  // Ken — genesis holder, full authority
  founder: [
    "workspace:admin",
  ],

  // Kalyn — successor, full admin + succession invocation
  successor: [
    "workspace:admin",
    "succession:invoke",
  ],

  // Lorrie, Katie — staff operators with own mailbox + shared resources
  officer: (mailbox) => [
    `mail:read:${mailbox}`,
    `mail:send:${mailbox}`,
    `mail:manage:${mailbox}`,
    "mail:read:info",
    "mail:send:info",
    "docs:read:*",
    "docs:write:*",
    "secure:channel:general",
    "secure:channel:decisions",
    "succession:co-sign",
  ],
};

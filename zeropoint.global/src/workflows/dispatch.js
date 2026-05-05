/**
 * Workflow dispatcher — routes inbound workflow emails to handlers.
 *
 * When the email router classifies a message as type: 'workflow',
 * it passes here to be dispatched to the correct handler.
 */

import { handleArchive } from "./archive.js";
import { handleTask } from "./task.js";
import { handlePublish } from "./publish.js";
import { handleInquiry } from "./inquiry.js";
import { handleDmarc } from "./dmarc.js";
import { emitReceipt } from "../auth/receipts.js";

const HANDLERS = {
  archive: handleArchive,
  task: handleTask,
  publish: handlePublish,
  route: handleInquiry,
  dmarc: handleDmarc,
};

/**
 * Dispatch a workflow email to the appropriate handler.
 *
 * @param {Object} env       - Cloudflare bindings
 * @param {Object} parsed    - Parsed email (from parser.js)
 * @param {Object} route     - Route result (from router.js)
 * @param {string} messageId - Stored message ID
 * @returns {Promise<{ok: boolean, handler: string, result?: any, error?: string}>}
 */
export async function dispatchWorkflow(env, parsed, route, messageId) {
  const handler = HANDLERS[route.handler];

  if (!handler) {
    console.error(
      JSON.stringify({
        event: "workflow:unknown_handler",
        handler: route.handler,
        messageId,
        from: parsed.from,
      })
    );
    return { ok: false, handler: route.handler, error: "unknown handler" };
  }

  try {
    const result = await handler(env, parsed, messageId);

    await emitReceipt(env, {
      operatorId: "system",
      claim: `workflow:${route.handler}`,
      subject: messageId,
      metadata: {
        from: parsed.from,
        handler: route.handler,
        resultType: result.type,
        resultId: result.id,
      },
    });

    console.log(
      JSON.stringify({
        event: `workflow:${route.handler}:completed`,
        messageId,
        resultId: result.id,
        from: parsed.from,
      })
    );

    return { ok: true, handler: route.handler, result };
  } catch (err) {
    console.error(
      JSON.stringify({
        event: `workflow:${route.handler}:error`,
        messageId,
        from: parsed.from,
        error: err.message,
        stack: err.stack,
      })
    );

    return { ok: false, handler: route.handler, error: err.message };
  }
}

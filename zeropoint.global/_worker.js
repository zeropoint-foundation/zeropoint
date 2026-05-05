/**
 * ZeroPoint Global — Worker
 *
 * Serves static assets with legacy redirects.
 */

const REDIRECTS = {
  "/playground.html": "/lab/sim01.html",
  "/playground": "/lab/",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const dest = REDIRECTS[url.pathname];
    if (dest) {
      return Response.redirect(new URL(dest, url.origin).href, 301);
    }
    return env.ASSETS.fetch(request);
  },
};

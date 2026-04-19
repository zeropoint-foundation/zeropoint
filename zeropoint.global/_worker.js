/**
 * ZeroPoint Global — Pages Advanced Mode Worker
 *
 * Serves static assets normally. Intercepts /playground to inject
 * map credentials from encrypted environment secrets.
 *
 * Secrets (set via wrangler or dashboard):
 *   GOOGLE_API_KEY — Google Maps Platform API key
 *   CESIUM_TOKEN   — Cesium Ion access token
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\.html$/, '').replace(/\/$/, '') || '/';

    // Fetch the static asset from Pages
    const response = await env.ASSETS.fetch(request);

    // Only rewrite the playground page
    if (path !== '/playground') {
      return response;
    }

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('text/html')) {
      return response;
    }

    const googleApiKey = env.GOOGLE_API_KEY || '';
    const cesiumToken = env.CESIUM_TOKEN || '';

    // If neither key is configured, pass through unmodified
    if (!googleApiKey && !cesiumToken) {
      return response;
    }

    // Inject credentials as <meta> tags into <head>
    return new HTMLRewriter()
      .on('head', {
        element(el) {
          if (googleApiKey) {
            el.prepend(
              `<meta name="zp-google-api-key" content="${escapeAttr(googleApiKey)}">`,
              { html: true }
            );
          }
          if (cesiumToken) {
            el.prepend(
              `<meta name="zp-cesium-token" content="${escapeAttr(cesiumToken)}">`,
              { html: true }
            );
          }
        },
      })
      .transform(response);
  },
};

/** Escape a string for safe insertion into an HTML attribute value */
function escapeAttr(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

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

    // Debug endpoint — remove after confirming secrets work
    if (path === '/_debug/env') {
      const keys = Object.keys(env).filter(k => k !== 'ASSETS');
      const has = {
        GOOGLE_API_KEY: !!env.GOOGLE_API_KEY,
        CESIUM_TOKEN: !!env.CESIUM_TOKEN,
        envKeys: keys,
      };
      return new Response(JSON.stringify(has, null, 2), {
        headers: { 'content-type': 'application/json' },
      });
    }

    // Fetch the static asset
    const response = await env.ASSETS.fetch(request);

    // Add debug header to confirm Worker is executing
    const newHeaders = new Headers(response.headers);
    newHeaders.set('x-zp-worker', 'active');

    // Only rewrite the playground page
    if (path !== '/playground') {
      return new Response(response.body, { status: response.status, headers: newHeaders });
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

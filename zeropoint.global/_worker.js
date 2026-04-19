/**
 * ZeroPoint Global — Worker with credential injection
 *
 * Serves static assets normally. Intercepts /playground to inject
 * map credentials from encrypted environment secrets via HTMLRewriter.
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\.html$/, '').replace(/\/$/, '') || '/';

    // Debug endpoint — remove after confirming injection works
    if (path === '/_debug/env') {
      const keys = Object.keys(env).filter(k => k !== 'ASSETS');
      return new Response(JSON.stringify({
        GOOGLE_API_KEY: !!env.GOOGLE_API_KEY,
        CESIUM_TOKEN: !!env.CESIUM_TOKEN,
        envKeys: keys,
      }, null, 2), {
        headers: { 'content-type': 'application/json' },
      });
    }

    // For non-playground routes, pass through to static assets
    if (path !== '/playground') {
      return env.ASSETS.fetch(request);
    }

    // Playground route — fetch asset and inject credentials
    const googleApiKey = env.GOOGLE_API_KEY || '';
    const cesiumToken = env.CESIUM_TOKEN || '';

    // If no keys configured, just serve static
    if (!googleApiKey && !cesiumToken) {
      return env.ASSETS.fetch(request);
    }

    const response = await env.ASSETS.fetch(request);

    // Build the meta tags to inject
    let inject = '';
    if (cesiumToken) {
      inject += `<meta name="zp-cesium-token" content="${escapeAttr(cesiumToken)}">`;
    }
    if (googleApiKey) {
      inject += `<meta name="zp-google-api-key" content="${escapeAttr(googleApiKey)}">`;
    }

    // Use HTMLRewriter to prepend meta tags into <head>
    return new HTMLRewriter()
      .on('head', {
        element(el) {
          el.prepend(inject, { html: true });
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

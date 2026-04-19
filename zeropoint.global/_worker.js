/**
 * ZeroPoint Global — Worker with credential injection
 *
 * Serves static assets normally. Intercepts /playground to inject
 * map credentials from encrypted environment secrets via string
 * replacement (more reliable than HTMLRewriter with asset responses).
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const raw = url.pathname;
    const path = raw.replace(/\.html$/, '').replace(/\/$/, '') || '/';

    // Debug endpoint — remove after confirming injection works
    if (path === '/_debug/env') {
      return new Response(JSON.stringify({
        GOOGLE_API_KEY: !!env.GOOGLE_API_KEY,
        CESIUM_TOKEN: !!env.CESIUM_TOKEN,
        rawPath: raw,
        normalizedPath: path,
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

    // Fetch the static asset
    const response = await env.ASSETS.fetch(request);

    // Read the full HTML body as text
    const html = await response.text();

    // Build the meta tags to inject
    let inject = '';
    if (cesiumToken) {
      inject += `<meta name="zp-cesium-token" content="${escapeAttr(cesiumToken)}">`;
    }
    if (googleApiKey) {
      inject += `<meta name="zp-google-api-key" content="${escapeAttr(googleApiKey)}">`;
    }

    // Inject right after <head> (or <head ...>)
    const modified = html.replace(
      /(<head[^>]*>)/i,
      '$1\n' + inject
    );

    // Return new response with same headers but modified body
    const newHeaders = new Headers(response.headers);
    newHeaders.set('x-zp-worker', 'injected');
    newHeaders.delete('content-length'); // length changed

    return new Response(modified, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
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

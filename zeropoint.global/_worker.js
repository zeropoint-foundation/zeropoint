/**
 * ZeroPoint Global — Worker with credential injection
 *
 * Serves static assets normally. Intercepts /playground to inject
 * map credentials from encrypted environment secrets.
 *
 * Key fix: explicitly requests /playground.html from the ASSETS binding
 * rather than passing through the original request URL, which may not
 * resolve correctly through the asset binding's extension handling.
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const raw = url.pathname;
    const path = raw.replace(/\.html$/, '').replace(/\/$/, '') || '/';

    // Debug endpoint — remove after confirming injection works
    if (path === '/_debug/env') {
      // Also test the asset fetch to diagnose issues
      let assetStatus = 'not tested';
      let assetType = '';
      let assetFirst100 = '';
      let hasHeadTag = false;
      try {
        const testUrl = new URL('/playground.html', url.origin);
        const testResp = await env.ASSETS.fetch(new Request(testUrl.toString()));
        assetStatus = testResp.status;
        assetType = testResp.headers.get('content-type') || '';
        const body = await testResp.text();
        assetFirst100 = body.substring(0, 100);
        hasHeadTag = /<head/i.test(body);
      } catch (e) {
        assetStatus = 'error: ' + e.message;
      }
      return new Response(JSON.stringify({
        GOOGLE_API_KEY: !!env.GOOGLE_API_KEY,
        CESIUM_TOKEN: !!env.CESIUM_TOKEN,
        rawPath: raw,
        normalizedPath: path,
        assetFetchStatus: assetStatus,
        assetContentType: assetType,
        assetFirst100,
        assetHasHead: hasHeadTag,
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
      const resp = await env.ASSETS.fetch(request);
      return new Response(resp.body, {
        status: resp.status,
        headers: { ...Object.fromEntries(resp.headers), 'x-zp-worker': 'no-keys' },
      });
    }

    // Explicitly request /playground.html — the ASSETS binding may not
    // resolve extensionless URLs like /playground to playground.html
    const assetUrl = new URL('/playground.html', url.origin);
    const assetRequest = new Request(assetUrl.toString(), {
      method: request.method,
      headers: request.headers,
    });
    const response = await env.ASSETS.fetch(assetRequest);

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

    // Diagnostic headers — visible in DevTools Network tab
    const newHeaders = new Headers(response.headers);
    newHeaders.set('x-zp-worker', 'injected');
    newHeaders.set('x-zp-path', raw);
    newHeaders.set('x-zp-asset-status', String(response.status));
    newHeaders.set('x-zp-html-length', String(html.length));
    newHeaders.set('x-zp-modified-length', String(modified.length));
    newHeaders.set('x-zp-had-head', String(/<head/i.test(html)));
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

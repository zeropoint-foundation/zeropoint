/**
 * Cloudflare Pages Function — injects map credentials into playground.html
 *
 * Reads GOOGLE_API_KEY and CESIUM_TOKEN from Cloudflare Pages environment
 * variables (set as encrypted secrets in the dashboard) and injects them
 * as <meta> tags into the <head> before the page reaches the browser.
 *
 * Setup:
 *   1. Deploy this file at functions/playground.js
 *   2. In Cloudflare Pages dashboard → Settings → Environment variables:
 *      - GOOGLE_API_KEY = your Google Maps Platform key
 *      - CESIUM_TOKEN   = your Cesium Ion access token
 *      (mark both as "Encrypt" for production)
 */
export async function onRequest(context) {
  // Fetch the static playground.html from the origin
  const response = await context.next();

  // Only rewrite HTML responses
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) {
    return response;
  }

  const googleApiKey = context.env.GOOGLE_API_KEY || '';
  const cesiumToken = context.env.CESIUM_TOKEN || '';

  // If neither key is configured, pass through unmodified
  if (!googleApiKey && !cesiumToken) {
    return response;
  }

  // Use HTMLRewriter to inject meta tags into <head>
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
}

/** Escape a string for safe insertion into an HTML attribute value */
function escapeAttr(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

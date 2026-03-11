// ZeroPoint Global — Cloudflare Worker
//
// Serves static assets for the public site and proxies /api/* requests
// to the zp-server backend on Hetzner (zp-playground).
//
// Static assets: served from the assets binding (Cloudflare Workers Static Assets)
// API routes: proxied to the backend with CORS headers added

const BACKEND_ORIGIN = 'http://89.167.86.60:3000';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Proxy /api/* requests to the Hetzner backend
    if (url.pathname.startsWith('/api/')) {
      return handleApiProxy(request, url);
    }

    // Everything else: serve from static assets
    // The assets binding is automatically available in Workers with Assets
    return env.ASSETS.fetch(request);
  },
};

async function handleApiProxy(request, url) {
  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(),
    });
  }

  // Build the backend URL
  const backendUrl = new URL(url.pathname + url.search, BACKEND_ORIGIN);

  // Forward the request to the backend
  const backendRequest = new Request(backendUrl.toString(), {
    method: request.method,
    headers: request.headers,
    body: request.method !== 'GET' && request.method !== 'HEAD'
      ? request.body
      : undefined,
  });

  try {
    const response = await fetch(backendRequest);

    // Clone response and add CORS headers
    const newHeaders = new Headers(response.headers);
    for (const [key, value] of Object.entries(corsHeaders())) {
      newHeaders.set(key, value);
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: 'Backend unavailable', detail: err.message }),
      {
        status: 502,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(),
        },
      }
    );
  }
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': 'https://zeropoint.global',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

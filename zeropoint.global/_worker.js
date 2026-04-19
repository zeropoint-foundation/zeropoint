/**
 * ZeroPoint Global — Worker (passthrough)
 *
 * Serves all requests via the static ASSETS binding.
 * Map credentials are hardcoded in playground.html.
 */
export default {
  async fetch(request, env) {
    return env.ASSETS.fetch(request);
  },
};

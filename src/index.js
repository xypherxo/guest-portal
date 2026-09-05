// Guest Portal — UniFi external captive portal auth handler
//
// Architecture:
//   - Static assets (index.html, ttt-logo.png) served from ./public via
//     the Workers "assets" binding — those requests never reach this code.
//   - This handler manages /auth: guests click "Accept" → portal POSTs the
//     client MAC here → we log in to the UniFi controller via
//     CONTROLLER_URL and run authorize-guest.
//
// Environment (Settings → Variables and Secrets):
//   CONTROLLER_URL  (Secret) e.g. https://unifi.thetechnicaltouch.com.au
//   CONTROLLER_USER (Secret) svc-guestportal
//   CONTROLLER_PASS (Secret) the service account password
//   SITE            (Text)   default

const PORTAL_ORIGIN = "https://guest.thetechnicaltouch.com.au";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ---- Routing -----------------------------------------------------------
    // Everything except /auth is handled by the static asset binding
    // (env.ASSETS). This is a safety net — normally the assets config
    // intercepts these before the Worker code runs.
    if (url.pathname !== "/auth") {
      return env.ASSETS.fetch(request);
    }

    // ---- CORS + preflight ---------------------------------------------------
    const cors = {
      "Access-Control-Allow-Origin": PORTAL_ORIGIN,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "method not allowed" }, 405, cors);
    }

    // ---- Origin check (defence in depth; CORS alone is not enforcement) -----
    const origin = request.headers.get("Origin") || "";
    if (origin && origin !== PORTAL_ORIGIN) {
      return jsonResponse({ error: "forbidden origin" }, 403, cors);
    }

    // ---- Input validation ----------------------------------------------------
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: "invalid json" }, 400, cors);
    }

    const { mac, t } = body;

    // MAC must be exactly 6 colon-separated hex pairs — reject everything else
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac || "")) {
      return jsonResponse({ error: "invalid mac" }, 400, cors);
    }

    // Session duration: clamp to sane bounds (max 24h, default 8h)
    const seconds = parseInt(t || "28800", 10);
    const clampedSeconds = Math.min(Math.max(seconds || 28800, 3600), 86400);
    const minutes = Math.floor(clampedSeconds / 60);

    // ---- Validate configuration -----------------------------------------------
    if (!env.CONTROLLER_URL || !env.CONTROLLER_USER || !env.CONTROLLER_PASS || !env.SITE) {
      return jsonResponse({ error: "worker not configured" }, 500, cors);
    }

    const controllerUrl = env.CONTROLLER_URL.replace(/\/+$/, ""); // strip trailing slashes

    // ---- Controller login -----------------------------------------------------
    let cookie;
    try {
      const loginRes = await fetch(`${controllerUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: env.CONTROLLER_USER,
          password: env.CONTROLLER_PASS,
          rememberMe: true,
        }),
      });

      if (!loginRes.ok) {
        throw new Error(`controller login failed (${loginRes.status})`);
      }

      const setCookie = loginRes.headers.get("set-cookie");
      if (!setCookie) {
        throw new Error("controller returned no session cookie");
      }
      // UniFi may return multiple cookies; take the first (the session token)
      cookie = setCookie.split(";")[0];
    } catch (err) {
      return jsonResponse(
        { error: "could not reach controller", detail: err.message },
        502,
        cors
      );
    }

    // ---- Authorize the guest MAC ------------------------------------------------
    try {
      const authRes = await fetch(
        `${controllerUrl}/proxy/network/api/s/${env.SITE}/cmd/stamgr`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Cookie: cookie,
          },
          body: JSON.stringify({
            cmd: "authorize-guest",
            mac: mac.toLowerCase(),
            minutes: minutes,
          }),
        }
      );

      if (!authRes.ok) {
        const detail = await authRes.text().catch(() => "");
        throw new Error(`authorize failed (${authRes.status}): ${detail.slice(0, 200)}`);
      }

      return jsonResponse({ ok: true, minutes }, 200, cors);
    } catch (err) {
      return jsonResponse(
        { error: "authorization failed", detail: err.message },
        502,
        cors
      );
    }
  },
};

// ---- Helpers -----------------------------------------------------------------
function jsonResponse(obj, status, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

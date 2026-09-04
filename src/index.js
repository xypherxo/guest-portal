export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname !== "/auth") {
      return env.ASSETS.fetch(request);   // fall through to static assets
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const cors = {
      "Access-Control-Allow-Origin": "https://guests.thetechnicaltouch.com.au",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    // Hardening: validate MAC shape before touching the controller
    const { mac, t } = await request.json().catch(() => ({}));
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac || "")) {
      return json({ error: "invalid mac" }, 400, cors);
    }

    try {
      const loginRes = await fetch(`${env.CONTROLLER_URL}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: env.CONTROLLER_USER,
          password: env.CONTROLLER_PASS,
          rememberMe: true,
        }),
      });
      if (!loginRes.ok) throw new Error("controller login failed");
      const cookie = loginRes.headers.get("set-cookie").split(";")[0];

      const authRes = await fetch(
        `${env.CONTROLLER_URL}/proxy/network/api/s/${env.SITE}/cmd/stamgr`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json", Cookie: cookie },
          body: JSON.stringify({
            cmd: "authorize-guest",
            mac: mac.toLowerCase(),
            minutes: Math.floor(parseInt(t || "480", 10) / 60),
          }),
        }
      );
      if (!authRes.ok) throw new Error("authorize failed: " + (await authRes.text()));

      return json({ ok: true }, 200, cors);
    } catch (err) {
      return json({ error: err.message }, 502, cors);
    }
  },
};

function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

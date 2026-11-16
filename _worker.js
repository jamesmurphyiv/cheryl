// CherylX Pages gate - server-side password check for every request.
// Password lives in the Pages secret GATE_PASS (never in the repo).
// Cookie is SHA-256(salt + password), so no session store is needed.

const SALT = "cherylx-gate-v1";

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>CHERYL X</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; background: #000; }
  body {
    display: flex; align-items: center; justify-content: center;
    font-family: 'Courier New', monospace; color: #cfeef5;
  }
  .gate { text-align: center; width: min(320px, 86vw); }
  .brand { font-size: 22px; letter-spacing: 10px; color: #7fd8e8; margin-bottom: 6px; }
  .sub { font-size: 10px; letter-spacing: 4px; color: #4a6a72; margin-bottom: 34px; }
  input[type=password] {
    width: 100%; padding: 12px 14px; background: #060b0d;
    border: 1px solid #1d3a42; color: #cfeef5; font-family: inherit;
    font-size: 14px; letter-spacing: 3px; text-align: center; outline: none;
  }
  input[type=password]:focus { border-color: #3f7d8c; }
  button {
    width: 100%; margin-top: 12px; padding: 12px; background: transparent;
    border: 1px solid #2b5561; color: #7fd8e8; font-family: inherit;
    font-size: 12px; letter-spacing: 5px; cursor: pointer;
  }
  button:hover { background: #0a1a1f; }
  .err { color: #e86a6a; font-size: 10px; letter-spacing: 2px; margin-top: 14px; min-height: 12px; }
  form { width: 100%; }
</style>
</head>
<body>
  <div class="gate">
    <div class="brand">CHERYL X</div>
    <div class="sub">AUTHORIZED ACCESS ONLY</div>
    <form method="POST" action="/__gate">
      <input type="password" name="pass" autocomplete="current-password" autofocus aria-label="Password">
      <button type="submit">ENTER</button>
    </form>
    <div class="err">__ERR__</div>
  </div>
</body>
</html>`;

async function sha256hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function loginPage(err = "") {
  return new Response(LOGIN_HTML.replace("__ERR__", err), {
    status: 401,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > -1) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pass = env.GATE_PASS || "";
    if (!pass) return env.ASSETS.fetch(request); // gate not configured: fail open
    const expected = await sha256hex(SALT + pass);

    if (url.pathname === "/__gate" && request.method === "POST") {
      try {
        const form = await request.formData();
        const attempt = String(form.get("pass") || "");
        if (attempt && (await sha256hex(SALT + attempt)) === expected) {
          return new Response(null, {
            status: 303,
            headers: {
              Location: "/",
              "Set-Cookie": `cherylx_gate=${expected}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
              "Cache-Control": "no-store",
            },
          });
        }
        return loginPage("ACCESS DENIED");
      } catch (e) {
        return loginPage("ACCESS DENIED");
      }
    }

    const cookies = parseCookies(request.headers.get("Cookie"));
    const authed = cookies["cherylx_gate"] === expected;

    // Licensed wake-up song: served only behind the gate, out of KV.
    // The file is never in the repo, so the public GitHub Pages mirror has no copy.
    if (url.pathname === "/wake-audio"){
      if (!authed) return new Response("locked", { status: 401 });
      if (!env.AUDIO) return new Response("audio not configured", { status: 404 });
      const buf = await env.AUDIO.get("clash-should-i-stay", "arrayBuffer");
      if (!buf) return new Response("song missing", { status: 404 });
      return new Response(buf, {
        headers: { "Content-Type": "audio/mpeg", "Cache-Control": "no-store", "Content-Length": String(buf.byteLength) },
      });
    }

    // Rolling 30-day cookie: every authed visit re-issues it, so the alarm
    // profile stays unlocked as long as the alarm keeps firing.
    if (authed){
      const resp = await env.ASSETS.fetch(request);
      const r = new Response(resp.body, resp);
      r.headers.append("Set-Cookie", `cherylx_gate=${expected}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
      return r;
    }

    return loginPage();
  },
};

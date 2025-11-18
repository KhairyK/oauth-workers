// ====================================================
// UTIL: JWT
// ====================================================
async function createJWT(payload, secret) {
  const encoder = new TextEncoder();

  const header = { alg: "HS256", typ: "JWT" };

  const base64url = (obj) =>
    btoa(JSON.stringify(obj))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const headerEncoded = base64url(header);
  const payloadEncoded = base64url(payload);
  const toSign = `${headerEncoded}.${payloadEncoded}`;

  const signature = await crypto.subtle.sign(
    { name: "HMAC" },
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    ),
    encoder.encode(toSign)
  );

  const signatureEncoded = btoa(
    String.fromCharCode(...new Uint8Array(signature))
  )
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${toSign}.${signatureEncoded}`;
}

async function verifyJWT(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [header, payload, signature] = parts;
  const toVerify = `${header}.${payload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const newSignature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(toVerify)
  );

  const signatureEncoded = btoa(
    String.fromCharCode(...new Uint8Array(newSignature))
  )
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  if (signatureEncoded !== signature) return null;

  const json = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));

  if (json.exp < Math.floor(Date.now() / 1000)) return null;

  return json;
}

// ====================================================
// HANDLER
// ====================================================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ===============================================
    // 1) ROUTE: GOOGLE LOGIN
    // ===============================================
    if (url.pathname === "/auth/google") {
      const googleURL =
        "https://accounts.google.com/o/oauth2/v2/auth?" +
        new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          redirect_uri: env.GOOGLE_REDIRECT_URI,
          response_type: "code",
          scope: "openid email profile",
          access_type: "offline",
          prompt: "consent",
        });

      return Response.redirect(googleURL, 302);
    }

    // ===============================================
    // 2) ROUTE: CALLBACK
    // ===============================================
    if (url.pathname === "/auth/google/callback") {
      const code = url.searchParams.get("code");
      if (!code) return new Response("NO_CODE");

      // Tukar code → token
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          code,
          redirect_uri: env.GOOGLE_REDIRECT_URI,
          grant_type: "authorization_code",
        }),
      });

      const token = await tokenRes.json();
      if (!token.access_token) return new Response("TOKEN_ERROR");

      // Ambil user data
      const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${token.access_token}` },
      });

      const user = await userRes.json();

      // ===================================
      // SIMPAN USER DI KV
      // key: user_<google_id>
      // ===================================
      await env.KV_USERS.put(`user_${user.id}`, JSON.stringify({
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        last_login: Date.now(),
      }));

      // ===================================
      // Bikin JWT
      // ===================================
      const jwt = await createJWT(
        {
          sub: user.id,
          email: user.email,
          name: user.name,
          picture: user.picture,
          exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7, // 7 hari
        },
        env.JWT_SECRET
      );

      // Cookie login
      const cookie = [
        `session_token=${jwt}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Max-Age=604800",
      ].join("; ");

      return new Response(null, {
        status: 302,
        headers: {
          "Set-Cookie": cookie,
          Location: "/dashboard",
        },
      });
    }

    // ===============================================
    // 3) ROUTE: PROTECTED DASHBOARD (JWT + KV)
    // ===============================================
    if (url.pathname === "/dashboard") {
      const cookieHeader = request.headers.get("Cookie") || "";
      const token = cookieHeader
        .split(";")
        .find((c) => c.trim().startsWith("session_token="));

      if (!token) return new Response("NOT_LOGGED_IN");

      const jwt = token.split("=")[1];

      const data = await verifyJWT(jwt, env.JWT_SECRET);
      if (!data) return new Response("INVALID_JWT");

      // Ambil user dari KV
      const user = await env.KV_USERS.get(`user_${data.sub}`, "json");

      return new Response(
        JSON.stringify(
          {
            message: "Dashboard Access Granted",
            user,
          },
          null,
          2
        ),
        {
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // DEFAULT
    return new Response("Worker Auth System Ready!");
  },
};

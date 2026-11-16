
const ALLOWED_ORIGIN = "https://aryankelvinq-hub.github.io";
const SESSION_HOURS = 6;

function json(data, status = 200, origin = ALLOWED_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin"
    }
  });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - padded.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function hmacSign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))
  );
}

async function createToken(env) {
  const payload = base64url(new TextEncoder().encode(JSON.stringify({
    role: "admin",
    exp: Date.now() + SESSION_HOURS * 60 * 60 * 1000
  })));

  const signature = base64url(
    await hmacSign(payload, env.ADMIN_SESSION_SECRET)
  );

  return payload + "." + signature;
}

async function verifyToken(request, env) {
  try {
    const header = request.headers.get("Authorization") || "";
    if (!header.startsWith("Bearer ")) return false;

    const token = header.slice(7);
    const parts = token.split(".");
    if (parts.length !== 2) return false;

    const expected = await hmacSign(parts[0], env.ADMIN_SESSION_SECRET);
    const actual = fromBase64url(parts[1]);

    if (expected.length !== actual.length) return false;

    let diff = 0;
    for (let i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ actual[i];
    }
    if (diff !== 0) return false;

    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64url(parts[0]))
    );

    return payload.role === "admin" && payload.exp > Date.now();
  } catch {
    return false;
  }
}

function encryptionKey(env) {
  const hex = env.PROVIDER_ENCRYPTION_KEY || "";
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("Invalid PROVIDER_ENCRYPTION_KEY");
  }

  return new Uint8Array(
    hex.match(/.{2}/g).map(x => parseInt(x, 16))
  );
}

async function providerEncrypt(plainText, env) {
  const key = await crypto.subtle.importKey(
    "raw",
    encryptionKey(env),
    "AES-GCM",
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plainText)
  );

  const combined = new Uint8Array(12 + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), 12);

  return base64url(combined);
}

async function providerDecrypt(cipherText, env) {
  const key = await crypto.subtle.importKey(
    "raw",
    encryptionKey(env),
    "AES-GCM",
    false,
    ["decrypt"]
  );

  const bytes = fromBase64url(cipherText);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bytes.slice(0, 12) },
    key,
    bytes.slice(12)
  );

  return new TextDecoder().decode(decrypted);
}

function supabaseHeaders(env, extra = {}) {
  return {
    "apikey": env.SUPABASE_SECRET_KEY,
    "Authorization": "Bearer " + env.SUPABASE_SECRET_KEY,
    "Content-Type": "application/json",
    ...extra
  };
}

async function dbRequest(env, table, query = "", options = {}) {
  const url = env.SUPABASE_URL.replace(/\/$/, "") +
    "/rest/v1/" + table + query;

  return fetch(url, {
    method: options.method || "GET",
    headers: supabaseHeaders(env, options.headers || {}),
    body: options.body ? JSON.stringify(options.body) : undefined
  });
}

async function handleAdmin(request, env, pathname) {
  if (pathname === "/admin/login" && request.method === "POST") {
    const body = await request.json();

    const password = body.password || body.admin_password;
    if (!password || password !== env.ADMIN_PASSWORD) {
      return json({ error: "Invalid admin password" }, 401);
    }

    const token = await createToken(env);
    return json({ success: true, token });
  }

  const valid = await verifyToken(request, env);
  if (!valid) {
    return json({ error: "Unauthorized. Please login again." }, 401);
  }

  if (pathname === "/admin/verify" && request.method === "GET") {
    return json({ success: true, authenticated: true });
  }

  if (pathname === "/admin/tools" && request.method === "GET") {
    const response = await dbRequest(
      env,
      "lao_ai_tools",
      "?select=tool_name,display_name,description,enabled&order=display_name.asc"
    );

    if (!response.ok) {
      return json({ error: "Unable to load tools", detail: await response.text() }, 500);
    }

    return json({ tools: await response.json() });
  }

  if (pathname === "/admin/tools" && request.method === "POST") {
    const body = await request.json();

    if (typeof body.tool_name !== "string" ||
        typeof body.enabled !== "boolean") {
      return json({ error: "tool_name and enabled are required" }, 400);
    }

    const response = await dbRequest(
      env,
      "lao_ai_tools",
      "?tool_name=eq." + encodeURIComponent(body.tool_name),
      {
        method: "PATCH",
        headers: { "Prefer": "return=minimal" },
        body: { enabled: body.enabled }
      }
    );

    if (!response.ok) {
      return json({ error: "Tool update failed", detail: await response.text() }, 500);
    }

    return json({ success: true, message: "Tool updated successfully" });
  }

  if (pathname === "/admin/providers" && request.method === "GET") {
    const response = await dbRequest(
      env,
      "lao_ai_providers",
      "?select=id,provider_name,display_name,base_url,models,enabled,created_at,updated_at&order=display_name.asc"
    );

    if (!response.ok) {
      return json({ error: "Unable to load providers", detail: await response.text() }, 500);
    }

    const providers = await response.json();
    return json({
      providers: providers.map(p => ({
        ...p,
        has_api_key: false
      }))
    });
  }

  if (pathname === "/admin/providers" && request.method === "POST") {
    const body = await request.json();

    const providerName = String(body.provider_name || "").trim();
    const displayName = String(body.display_name || "").trim();

    if (!providerName || !displayName) {
      return json({ error: "provider_name and display_name are required" }, 400);
    }

    if (!/^[a-zA-Z0-9_-]{2,60}$/.test(providerName)) {
      return json({ error: "Invalid provider_name" }, 400);
    }

    if (body.models !== undefined && !Array.isArray(body.models)) {
      return json({ error: "models must be an array" }, 400);
    }

    const record = {
      provider_name: providerName,
      display_name: displayName,
      base_url: body.base_url ? String(body.base_url).trim() : null,
      models: body.models || [],
      enabled: body.enabled === true,
      updated_at: new Date().toISOString()
    };

    if (body.api_key) {
      record.api_key_ciphertext = await providerEncrypt(
        String(body.api_key),
        env
      );
    }

    let response;

    if (body.id) {
      response = await dbRequest(
        env,
        "lao_ai_providers",
        "?id=eq." + encodeURIComponent(String(body.id)),
        {
          method: "PATCH",
          headers: { "Prefer": "return=minimal" },
          body: record
        }
      );
    } else {
      if (!body.api_key) {
        return json({ error: "API key is required for a new provider" }, 400);
      }

      response = await dbRequest(
        env,
        "lao_ai_providers",
        "",
        {
          method: "POST",
          headers: { "Prefer": "return=minimal" },
          body: record
        }
      );
    }

    if (!response.ok) {
      return json({ error: "Provider save failed", detail: await response.text() }, 500);
    }

    return json({ success: true, message: "Provider saved successfully" });
  }

  if (pathname === "/admin/providers" && request.method === "DELETE") {
    const body = await request.json();
    if (!body.id) return json({ error: "Provider id is required" }, 400);

    const response = await dbRequest(
      env,
      "lao_ai_providers",
      "?id=eq." + encodeURIComponent(String(body.id)),
      { method: "DELETE", headers: { "Prefer": "return=minimal" } }
    );

    if (!response.ok) {
      return json({ error: "Provider delete failed", detail: await response.text() }, 500);
    }

    return json({ success: true, message: "Provider deleted successfully" });
  }

  return json({ error: "Admin route not found" }, 404);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowedOrigin = origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN;

    if (request.method === "OPTIONS") {
      if (origin !== ALLOWED_ORIGIN) {
        return new Response(null, { status: 403 });
      }
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Vary": "Origin"
        }
      });
    }

    if (origin && origin !== ALLOWED_ORIGIN) {
      return json({ error: "Origin not allowed" }, 403);
    }

    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (pathname === "/health" && request.method === "GET") {
        return json({ status: "online", service: "LAO AI Backend" }, 200, allowedOrigin);
      }

      if (pathname.startsWith("/admin/")) {
        return await handleAdmin(request, env, pathname);
      }

      return json({ error: "Not found" }, 404, allowedOrigin);
    } catch (error) {
      return json({
        error: "Internal server error",
        message: error.message || "Unknown error"
      }, 500, allowedOrigin);
    }
  }
};
        

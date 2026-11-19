const ALLOWED_ORIGIN = "https://aryankelvinq-hub.github.io";
const SESSION_HOURS = 6;
const MAX_BODY_SIZE = 100000;
const AI_TEST_MODEL = "@cf/meta/llama-3.1-8b-instruct";
const CHAT_MODEL = "@cf/meta/llama-3.1-8b-instruct";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin",
      "Cache-Control": "no-store"
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
  if (!secret) throw new Error("Session secret missing");
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

    const parts = header.slice(7).split(".");
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
    throw new Error("Provider encryption configuration missing");
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
  const result = new Uint8Array(12 + encrypted.byteLength);
  result.set(iv);
  result.set(new Uint8Array(encrypted), 12);
  return base64url(result);
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
  if (bytes.length <= 12) throw new Error("Invalid encrypted key");

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bytes.slice(0, 12) },
    key,
    bytes.slice(12)
  );
  return new TextDecoder().decode(decrypted);
}

function supabaseHeaders(env, extra = {}) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) {
    throw new Error("Database configuration missing");
  }
  return {
    "apikey": env.SUPABASE_SECRET_KEY,
    "Authorization": "Bearer " + env.SUPABASE_SECRET_KEY,
    "Content-Type": "application/json",
    ...extra
  };
}

async function dbRequest(env, table, query = "", options = {}) {
  const url = env.SUPABASE_URL.replace(/\/+$/, "") +
    "/rest/v1/" + table + query;

  return fetch(url, {
    method: options.method || "GET",
    headers: supabaseHeaders(env, options.headers || {}),
    body: options.body ? JSON.stringify(options.body) : undefined
  });
}

async function readBody(request) {
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_SIZE) {
    throw new Error("Request too large");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Invalid JSON body");
  }
}

function validBaseUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(String(value).trim());
    if (url.protocol !== "https:") return false;
    return url.toString().replace(/\/$/, "");
  } catch {
    return false;
  }
}

// Empty response fix — reasoning_content ko content mein promote karo
function normalizeAIOutput(result) {
  let output = result?.response || result?.choices?.[0]?.message?.content || "";

  if ((!output || !output.trim()) && result?.choices?.[0]?.message?.reasoning_content) {
    output = result.choices[0].message.reasoning_content;
  }

  return typeof output === "string" ? output.trim() : "";
}

// ===== PUBLIC CHAT ENDPOINT =====
async function handleChat(request, env) {
  if (request.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  if (!env.AI || typeof env.AI.run !== "function") {
    return json({ success: false, error: "AI binding not configured" }, 503);
  }

  const body = await readBody(request);
  const messages = body.messages;

  if (!Array.isArray(messages) || messages.length === 0 || messages.length > 20) {
    return json({ success: false, error: "Invalid messages array (1-20 allowed)" }, 400);
  }

  for (const m of messages) {
    if (!m || typeof m.content !== "string" || m.content.length > 4000) {
      return json({ success: false, error: "Each message must be a string under 4000 chars" }, 400);
    }
    if (!["user", "assistant", "system"].includes(m.role)) {
      return json({ success: false, error: "Invalid role" }, 400);
    }
  }

  try {
    const result = await env.AI.run(CHAT_MODEL, {
      messages: [
        {
          role: "system",
          content: "You are LAO AI assistant. Always reply in the same language the user writes in — Hindi, Hinglish, English, or Urdu. Be helpful, friendly, and concise."
        },
        ...messages.slice(-10)
      ],
      max_completion_tokens: 512,
      temperature: 0.7
    });

    const output = normalizeAIOutput(result);

    if (!output) {
      return json({
        success: false,
        error: "AI returned an empty response. Try rephrasing your message."
      }, 502);
    }

    return json({
      success: true,
      content: output,
      model: CHAT_MODEL
    });
  } catch (error) {
    return json({
      success: false,
      error: "AI request failed. Check Workers AI usage limits."
    }, 502);
  }
}

async function handleAdmin(request, env, pathname) {
  if (pathname === "/admin/login" && request.method === "POST") {
    const body = await readBody(request);
    const password = body.password || body.admin_password;

    if (!password || password !== env.ADMIN_PASSWORD) {
      return json({ error: "Invalid admin password" }, 401);
    }

    return json({
      success: true,
      token: await createToken(env)
    });
  }

  if (!(await verifyToken(request, env))) {
    return json({ error: "Unauthorized. Please login again." }, 401);
  }

  if (pathname === "/admin/verify" && request.method === "GET") {
    return json({ success: true, authenticated: true });
  }

  if (pathname === "/admin/ai-test" && request.method === "POST") {
    if (!env.AI || typeof env.AI.run !== "function") {
      return json({
        success: false,
        error: "Workers AI binding AI is not configured"
      }, 503);
    }

    const body = await readBody(request);
    const prompt = typeof body.prompt === "string"
      ? body.prompt.trim()
      : "";

    if (!prompt || prompt.length > 1000) {
      return json({
        success: false,
        error: "Prompt is required and must be under 1000 characters"
      }, 400);
    }

    try {
      const result = await env.AI.run(AI_TEST_MODEL, {
        messages: [
          {
            role: "system",
            content: "You are LAO AI assistant. Reply briefly and clearly in the user's language."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        max_completion_tokens: 256,
        temperature: 0.3
      });

      const output = normalizeAIOutput(result);

      if (!output) {
        return json({
          success: false,
          error: "AI returned an empty response"
        }, 502);
      }

      return json({
        success: true,
        model: AI_TEST_MODEL,
        response: output
      });
    } catch {
      return json({
        success: false,
        error: "Workers AI request failed. Check model availability and Cloudflare AI usage."
      }, 502);
    }
  }

  if (pathname === "/admin/tools" && request.method === "GET") {
    const response = await dbRequest(
      env,
      "lao_ai_tools",
      "?select=tool_name,display_name,description,enabled&order=display_name.asc"
    );

    if (!response.ok) {
      return json({ error: "Unable to load tools" }, 500);
    }
    return json({ tools: await response.json() });
  }

  if (pathname === "/admin/tools" && request.method === "POST") {
    const body = await readBody(request);

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
      return json({ error: "Tool update failed" }, 500);
    }
    return json({ success: true, message: "Tool updated successfully" });
  }

  if (pathname === "/admin/providers" && request.method === "GET") {
    const response = await dbRequest(
      env,
      "lao_ai_providers",
      "?select=id,provider_name,display_name,base_url,models,enabled,api_key_ciphertext,created_at,updated_at&order=display_name.asc"
    );

    if (!response.ok) {
      return json({ error: "Unable to load providers" }, 500);
    }

    const rows = await response.json();
    const providers = rows.map(p => ({
      id: p.id,
      provider_name: p.provider_name,
      display_name: p.display_name,
      base_url: p.base_url,
      models: p.models,
      enabled: p.enabled,
      has_api_key: Boolean(p.api_key_ciphertext),
      created_at: p.created_at,
      updated_at: p.updated_at
    }));

    return json({ providers });
  }

  if (pathname === "/admin/providers" && request.method === "POST") {
    const body = await readBody(request);

    const providerName = String(body.provider_name || "").trim();
    const displayName = String(body.display_name || "").trim();

    if (!/^[a-zA-Z0-9_-]{2,60}$/.test(providerName)) {
      return json({ error: "Invalid provider name" }, 400);
    }
    if (!displayName || displayName.length > 100) {
      return json({ error: "Valid display name is required" }, 400);
    }
    if (body.models !== undefined &&
        (!Array.isArray(body.models) ||
         body.models.length > 100 ||
         !body.models.every(m => typeof m === "string" && m.length <= 200))) {
      return json({ error: "Invalid models list" }, 400);
    }

    const baseUrl = validBaseUrl(body.base_url);
    if (body.base_url && !baseUrl) {
      return json({ error: "Base URL must be a valid HTTPS URL" }, 400);
    }

    const record = {
      provider_name: providerName,
      display_name: displayName,
      base_url: baseUrl,
      models: body.models || [],
      enabled: body.enabled === true,
      updated_at: new Date().toISOString()
    };

    if (body.api_key) {
      if (typeof body.api_key !== "string" || body.api_key.length > 5000) {
        return json({ error: "Invalid API key value" }, 400);
      }
      record.api_key_ciphertext = await providerEncrypt(body.api_key, env);
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
      return json({ error: "Provider save failed" }, 500);
    }

    return json({ success: true, message: "Provider saved successfully" });
  }

  if (pathname === "/admin/providers" && request.method === "DELETE") {
    const body = await readBody(request);
    if (!body.id) return json({ error: "Provider id is required" }, 400);

    const response = await dbRequest(
      env,
      "lao_ai_providers",
      "?id=eq." + encodeURIComponent(String(body.id)),
      {
        method: "DELETE",
        headers: { "Prefer": "return=minimal" }
      }
    );

    if (!response.ok) {
      return json({ error: "Provider delete failed" }, 500);
    }

    return json({ success: true, message: "Provider deleted successfully" });
  }

  return json({ error: "Admin route not found" }, 404);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      if (origin !== ALLOWED_ORIGIN) {
        return new Response(null, { status: 403 });
      }
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
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
        return json({ status: "online", service: "LAO AI Backend" });
      }

      if (pathname === "/api/chat" && request.method === "POST") {
        return await handleChat(request, env);
      }

      if (pathname.startsWith("/admin/")) {
        return await handleAdmin(request, env, pathname);
      }

      return json({ error: "Not found" }, 404);
    } catch (error) {
      const message =
        error.message === "Request too large" ? "Request too large" :
        error.message === "Invalid JSON body" ? "Invalid JSON body" :
        "Internal server error";

      const status =
        error.message === "Request too large" ? 413 :
        error.message === "Invalid JSON body" ? 400 :
        500;

      return json({ error: message }, status);
    }
  }
};

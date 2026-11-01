const crypto = require("crypto");

const GH_API = "https://api.github.com";
const GH_OAUTH = "https://github.com/login/oauth";
const RATE_WINDOW_MS = 60000;
const RATE_MAX = 30;
const STATE_TTL_SECONDS = 600;
const USERNAME_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$/;

const buckets = new Map();

function env(name, fallback = "") {
  const value = process.env[name];
  return value === undefined || value === "" ? fallback : value;
}

function targets() {
  return env("FOLLOW_TARGETS")
    .split(",")
    .map((t) => t.trim())
    .filter((t) => USERNAME_RE.test(t));
}

function clientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return String(forwarded).split(",")[0].trim();
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "unknown";
}

function rateLimited(ip) {
  const now = Date.now();
  if (buckets.size > 5000) {
    for (const [key, value] of buckets) {
      if (value.reset <= now) buckets.delete(key);
    }
  }
  const bucket = buckets.get(ip);
  if (!bucket || bucket.reset <= now) {
    buckets.set(ip, { count: 1, reset: now + RATE_WINDOW_MS });
    return { limited: false, remaining: RATE_MAX - 1, reset: now + RATE_WINDOW_MS };
  }
  bucket.count += 1;
  return {
    limited: bucket.count > RATE_MAX,
    remaining: Math.max(0, RATE_MAX - bucket.count),
    reset: bucket.reset
  };
}

function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function sign(value) {
  return crypto.createHmac("sha256", env("STATE_SECRET")).update(value).digest("base64url");
}

function createState(nonce) {
  const payload = b64url(JSON.stringify({ n: nonce, exp: Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS }));
  return `${payload}.${sign(payload)}`;
}

function verifyState(state, nonce) {
  if (typeof state !== "string" || typeof nonce !== "string") return false;
  const parts = state.split(".");
  if (parts.length !== 2) return false;
  const [payload, signature] = parts;
  if (!safeEqual(signature, sign(payload))) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (typeof data.exp !== "number" || data.exp < Math.floor(Date.now() / 1000)) return false;
    return safeEqual(data.n, nonce);
  } catch (e) {
    return false;
  }
}

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  header.split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx < 0) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Permissions-Policy", "interest-cohort=()");
}

function setCors(req, res) {
  const allowed = env("ALLOWED_ORIGINS")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
  const origin = req.headers.origin;
  if (origin && allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "x-api-key, content-type");
    res.setHeader("Access-Control-Max-Age", "600");
  }
}

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function redirect(res, location, extraHeaders = {}) {
  res.statusCode = 302;
  Object.keys(extraHeaders).forEach((k) => res.setHeader(k, extraHeaders[k]));
  res.setHeader("Location", location);
  res.end();
}

function requireApiKey(req, res) {
  const key = env("API_KEY");
  const provided = req.headers["x-api-key"];
  if (!key || typeof provided !== "string" || !safeEqual(provided, key)) {
    sendJson(res, 401, { ok: false, error: "unauthorized" });
    return false;
  }
  return true;
}

async function gh(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const headers = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "force-follow-api",
      ...(options.headers || {})
    };
    return await fetch(`${GH_API}${path}`, { ...options, headers, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function serverAuthHeader() {
  const token = env("GITHUB_TOKEN");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function resultRedirect(res, params, cookieClear) {
  const base = env("REDIRECT_URL");
  const headers = { "Set-Cookie": cookieClear };
  if (!base) return null;
  const url = new URL(base);
  Object.keys(params).forEach((k) => url.searchParams.set(k, String(params[k])));
  return redirect(res, url.toString(), headers);
}

async function handleLogin(req, res) {
  const list = targets();
  if (!env("GITHUB_CLIENT_ID") || !env("STATE_SECRET") || !env("BASE_URL") || list.length === 0) {
    return sendJson(res, 500, { ok: false, error: "server_not_configured" });
  }
  const nonce = crypto.randomBytes(24).toString("base64url");
  const state = createState(nonce);
  const params = new URLSearchParams({
    client_id: env("GITHUB_CLIENT_ID"),
    redirect_uri: `${env("BASE_URL")}/api/auth/callback`,
    scope: "user:follow",
    state,
    allow_signup: "false"
  });
  const cookie = `ff_nonce=${encodeURIComponent(nonce)}; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=${STATE_TTL_SECONDS}`;
  return redirect(res, `${GH_OAUTH}/authorize?${params.toString()}`, { "Set-Cookie": cookie });
}

async function handleCallback(req, res, url) {
  const clearCookie = "ff_nonce=; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=0";
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const nonce = parseCookies(req).ff_nonce;
  const fail = (status, error) => {
    if (resultRedirect(res, { status: "error", error }, clearCookie)) return;
    res.setHeader("Set-Cookie", clearCookie);
    sendJson(res, status, { ok: false, error });
  };

  if (!code || !state || !verifyState(state, nonce)) return fail(400, "invalid_state");

  const tokenRes = await fetch(`${GH_OAUTH}/access_token`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json", "User-Agent": "force-follow-api" },
    body: JSON.stringify({
      client_id: env("GITHUB_CLIENT_ID"),
      client_secret: env("GITHUB_CLIENT_SECRET"),
      code,
      redirect_uri: `${env("BASE_URL")}/api/auth/callback`
    })
  });
  if (!tokenRes.ok) return fail(502, "token_exchange_failed");
  const tokenData = await tokenRes.json();
  const accessToken = tokenData.access_token;
  if (!accessToken) return fail(400, "token_exchange_failed");

  const auth = { Authorization: `Bearer ${accessToken}` };
  const meRes = await gh("/user", { headers: auth });
  if (!meRes.ok) return fail(502, "user_lookup_failed");
  const me = await meRes.json();

  const results = [];
  for (const target of targets()) {
    if (me.login.toLowerCase() === target.toLowerCase()) {
      results.push({ target, status: "self" });
      continue;
    }
    const followRes = await gh(`/user/following/${encodeURIComponent(target)}`, {
      method: "PUT",
      headers: { ...auth, "Content-Length": "0" }
    });
    results.push({ target, status: followRes.status === 204 ? "followed" : "failed" });
  }

  await fetch(`${GH_API}/applications/${encodeURIComponent(env("GITHUB_CLIENT_ID"))}/token`, {
    method: "DELETE",
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "force-follow-api",
      Authorization: `Basic ${Buffer.from(`${env("GITHUB_CLIENT_ID")}:${env("GITHUB_CLIENT_SECRET")}`).toString("base64")}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ access_token: accessToken })
  }).catch(() => null);

  const allOk = results.every((r) => r.status === "followed" || r.status === "self");
  if (resultRedirect(res, { status: allOk ? "success" : "partial", user: me.login }, clearCookie)) return;
  res.setHeader("Set-Cookie", clearCookie);
  return sendJson(res, 200, { ok: allOk, user: me.login, results });
}

async function handleCheck(req, res, url) {
  if (!requireApiKey(req, res)) return;
  const username = url.searchParams.get("username");
  if (!username || !USERNAME_RE.test(username)) {
    return sendJson(res, 400, { ok: false, error: "invalid_username" });
  }
  const list = targets();
  if (list.length === 0) return sendJson(res, 500, { ok: false, error: "server_not_configured" });

  const results = await Promise.all(
    list.map(async (target) => {
      const r = await gh(`/users/${encodeURIComponent(username)}/following/${encodeURIComponent(target)}`, {
        headers: serverAuthHeader()
      });
      if (r.status === 204) return { target, following: true };
      if (r.status === 404) return { target, following: false };
      return { target, following: null, error: "lookup_failed" };
    })
  );
  const verified = results.every((r) => r.following === true);
  return sendJson(res, 200, { ok: true, username, verified, results });
}

async function handleStats(req, res) {
  if (!requireApiKey(req, res)) return;
  const list = targets();
  const stats = await Promise.all(
    list.map(async (target) => {
      const r = await gh(`/users/${encodeURIComponent(target)}`, { headers: serverAuthHeader() });
      if (!r.ok) return { target, error: "lookup_failed" };
      const d = await r.json();
      return { target, followers: d.followers, following: d.following, publicRepos: d.public_repos, avatar: d.avatar_url };
    })
  );
  return sendJson(res, 200, { ok: true, stats });
}

function handleHealth(res) {
  return sendJson(res, 200, {
    ok: true,
    service: "github-force-follow-api",
    time: new Date().toISOString(),
    configured: Boolean(env("GITHUB_CLIENT_ID") && env("GITHUB_CLIENT_SECRET") && env("STATE_SECRET") && env("BASE_URL") && targets().length)
  });
}

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  setCors(req, res);

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET, OPTIONS");
    return sendJson(res, 405, { ok: false, error: "method_not_allowed" });
  }

  const limit = rateLimited(clientIp(req));
  res.setHeader("X-RateLimit-Limit", String(RATE_MAX));
  res.setHeader("X-RateLimit-Remaining", String(limit.remaining));
  res.setHeader("X-RateLimit-Reset", String(Math.ceil(limit.reset / 1000)));
  if (limit.limited) {
    res.setHeader("Retry-After", String(Math.max(1, Math.ceil((limit.reset - Date.now()) / 1000))));
    return sendJson(res, 429, { ok: false, error: "rate_limited" });
  }

  let url;
  try {
    url = new URL(req.url, "http://localhost");
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: "bad_request" });
  }
  const path = url.pathname.replace(/^\/api/, "").replace(/\/+$/, "") || "/";

  try {
    if (path === "/" || path === "/health") return handleHealth(res);
    if (path === "/auth/login") return await handleLogin(req, res);
    if (path === "/auth/callback") return await handleCallback(req, res, url);
    if (path === "/check") return await handleCheck(req, res, url);
    if (path === "/stats") return await handleStats(req, res);
    return sendJson(res, 404, { ok: false, error: "not_found" });
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: "internal_error" });
  }
};

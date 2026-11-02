/**
 * KET 单词打卡 · 账号与进度同步云函数（CloudBase HTTP 函数 / Web 函数）
 *
 * 接口：
 *   POST /register   { username, password, invite, displayName? }  → { token, user }
 *   POST /login      { username, password }                → { token, user }
 *   GET  /progress   Authorization: Bearer <token>          → { payload, client_saved_at, updated_at }
 *   PUT  /progress   Authorization: Bearer <token> { payload, client_saved_at } → { ok }
 *   GET  /health     → { ok }
 *
 * 环境变量：
 *   CLOUDBASE_APIKEY    CloudBase API Key（service_role），访问 PG 用（与 interview-proxy 共用）
 *   KET_TOKEN_SECRET    签发登录令牌的密钥（缺失时退化为由 APIKEY 派生，建议显式配置）
 *   TCB_ENV             CloudBase 环境 ID
 *
 * 安全约定：
 *   - 密码只存 scrypt 哈希（每用户独立盐），明文不落库、不写日志
 *   - 令牌为 HMAC-SHA256 签名的自包含 token，90 天有效，服务端无会话表
 *   - 所有数据按 account_id 隔离，账号 id 只从令牌取，绝不从请求体取
 *   - 绝不回显 process.env / req.headers
 */

const http = require("http");
const https = require("https");
const crypto = require("crypto");

const PORT = process.env.PORT || 9000;

const OWN_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
};

const MAX_BODY_BYTES = 6 * 1024 * 1024;
const TOKEN_TTL_SECONDS = 90 * 24 * 3600;
const TABLES = {
  accounts: "ket_accounts",
  progress: "ket_progress",
  invites: "ket_invites",
};

function env(key, fallback) {
  const v = process.env[key];
  return v && String(v).trim() ? String(v).trim() : fallback;
}

function envId() {
  return env("TCB_ENV", "work-d1gs0jzrg2277d75e");
}

function restUrl(table) {
  return "https://" + envId() + ".api.tcloudbasegateway.com/v1/rdb/rest/" + table;
}

function tokenSecret() {
  const explicit = env("KET_TOKEN_SECRET", "");
  if (explicit) return explicit;
  // 兜底：由环境内已有的服务端密钥派生，避免"没配就发不出令牌"，但不依赖它做长期安全边界
  return crypto
    .createHash("sha256")
    .update("ket-words::" + env("CLOUDBASE_APIKEY", "no-key"))
    .digest("hex");
}

/* ───────────────────────── 通用响应 ───────────────────────── */

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, OWN_HEADERS);
  res.end(JSON.stringify(data));
}

function readRawBody(req) {
  return new Promise(function (resolve, reject) {
    let raw = "";
    let size = 0;
    let aborted = false;
    req.setEncoding("utf8");
    req.on("data", function (c) {
      if (aborted) return;
      size += Buffer.byteLength(c);
      if (size > MAX_BODY_BYTES) {
        aborted = true;
        reject(new Error("body_too_large"));
        return;
      }
      raw += c;
    });
    req.on("end", function () {
      if (aborted) return;
      resolve(raw);
    });
    req.on("error", reject);
  });
}

async function readJson(req) {
  const raw = await readRawBody(req);
  if (!raw) return {};
  try {
    const obj = JSON.parse(raw);
    return obj && typeof obj === "object" ? obj : {};
  } catch (e) {
    throw new Error("bad_json");
  }
}

/* ───────────────────────── PG（PostgREST 风格） ───────────────────────── */

function pgRequest(method, table, queryString, body, extraHeaders) {
  return new Promise(function (resolve) {
    const apiKey = env("CLOUDBASE_APIKEY", "");
    if (!apiKey) {
      resolve({ ok: false, status: 500, data: { error: "db_not_configured" } });
      return;
    }

    let target;
    try {
      target = new URL(restUrl(table) + (queryString ? "?" + queryString : ""));
    } catch (e) {
      resolve({ ok: false, status: 500, data: { error: "bad_db_url" } });
      return;
    }

    const payload = body ? JSON.stringify(body) : null;
    const headers = {
      Authorization: "Bearer " + apiKey,
      Accept: "application/json",
      ...(extraHeaders || {}),
    };
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }

    const req = https.request(
      {
        hostname: target.hostname,
        path: target.pathname + target.search,
        method: method,
        headers: headers,
        timeout: 20000,
      },
      function (pgRes) {
        let raw = "";
        pgRes.setEncoding("utf8");
        pgRes.on("data", function (c) {
          raw += c;
        });
        pgRes.on("end", function () {
          let parsed = null;
          if (raw) {
            try {
              parsed = JSON.parse(raw);
            } catch (e) {
              parsed = { error: "bad_json_from_db", raw: raw.slice(0, 300) };
            }
          }
          const status = pgRes.statusCode || 500;
          resolve({ ok: status >= 200 && status < 300, status: status, data: parsed });
        });
      }
    );

    req.on("timeout", function () {
      req.destroy(new Error("db_timeout"));
    });
    req.on("error", function (err) {
      resolve({ ok: false, status: 502, data: { error: "db_error", detail: err.message } });
    });

    if (payload) req.write(payload);
    req.end();
  });
}

/* ───────────────────────── 邀请码 ───────────────────────── */

/* 归一化：去掉连字符/空格、统一大写。展示与录入都用 formatInvite() 的形状 */
function normalizeInvite(input) {
  return String(input || "")
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, "");
}

function formatInvite(raw) {
  const s = String(raw || "");
  return s.length === 8 ? "KET-" + s.slice(0, 4) + "-" + s.slice(4) : s;
}

const INVITE_SELECT = "code,max_uses,used_count,expires_at,disabled";

function inviteReject(row) {
  if (!row) return { error: "invite_invalid", message: "邀请码不正确，请向发码的人确认" };
  if (row.disabled) return { error: "invite_disabled", message: "这个邀请码已经停用了" };
  if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) {
    return { error: "invite_expired", message: "这个邀请码已经过期了" };
  }
  if (Number(row.used_count) >= Number(row.max_uses)) {
    return { error: "invite_exhausted", message: "这个邀请码的名额已经用完了" };
  }
  return null;
}

async function readInvite(code) {
  const found = await pgRequest(
    "GET",
    TABLES.invites,
    "code=eq." + encodeURIComponent(code) + "&select=" + INVITE_SELECT + "&limit=1"
  );
  if (!found.ok) return { ok: false, status: 502 };
  const row = Array.isArray(found.data) ? found.data[0] : null;
  return { ok: true, row: row };
}

/* 原子占用一次名额：以 used_count 原值做 compare-and-swap，冲突则重读重试 */
async function claimInvite(code) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const got = await readInvite(code);
    if (!got.ok) {
      return { ok: false, status: 502, body: { error: "db_failed", message: "注册失败，请稍后重试" } };
    }
    const rejected = inviteReject(got.row);
    if (rejected) return { ok: false, status: 403, body: rejected };

    const next = Number(got.row.used_count) + 1;
    const patched = await pgRequest(
      "PATCH",
      TABLES.invites,
      "code=eq." + encodeURIComponent(code) + "&used_count=eq." + Number(got.row.used_count),
      { used_count: next },
      { Prefer: "return=representation" }
    );
    if (!patched.ok) {
      return { ok: false, status: 502, body: { error: "db_failed", message: "注册失败，请稍后重试" } };
    }
    if (Array.isArray(patched.data) && patched.data.length > 0) {
      return { ok: true, next: next };
    }
    /* 命中并发：别的实例刚占用过，重读后重试 */
  }
  return { ok: false, status: 429, body: { error: "invite_busy", message: "同时注册的人有点多，请再试一次" } };
}

async function releaseInvite(code, next) {
  /* 账号创建失败时把名额还回去，失败不影响主流程 */
  try {
    await pgRequest(
      "PATCH",
      TABLES.invites,
      "code=eq." + encodeURIComponent(code) + "&used_count=eq." + Number(next),
      { used_count: Number(next) - 1 },
      { Prefer: "return=minimal" }
    );
  } catch (e) {
    /* 归还失败只影响名额计数，不阻断响应 */
  }
}

/* ───────────────────────── 密码与令牌 ───────────────────────── */

const SCRYPT_KEYLEN = 64;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEYLEN).toString("hex");
  return "scrypt$" + salt + "$" + hash;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");
    if (parts.length !== 3 || parts[0] !== "scrypt") return false;
    const expected = Buffer.from(parts[2], "hex");
    const actual = crypto.scryptSync(password, parts[1], SCRYPT_KEYLEN);
    if (expected.length !== actual.length) return false;
    return crypto.timingSafeEqual(expected, actual);
  } catch (e) {
    return false;
  }
}

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function signToken(account) {
  const now = Math.floor(Date.now() / 1000);
  const body = {
    uid: Number(account.id),
    u: account.username,
    iat: now,
    exp: now + TOKEN_TTL_SECONDS,
  };
  const payload = b64url(JSON.stringify(body));
  const sig = b64url(
    crypto.createHmac("sha256", tokenSecret()).update(payload).digest()
  );
  return "v1." + payload + "." + sig;
}

function verifyToken(token) {
  const raw = String(token || "");
  const parts = raw.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const expected = b64url(
    crypto.createHmac("sha256", tokenSecret()).update(parts[1]).digest()
  );
  const a = Buffer.from(parts[2]);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let body;
  try {
    body = JSON.parse(
      Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")
    );
  } catch (e) {
    return null;
  }
  if (!body || !body.uid) return null;
  if (!body.exp || body.exp < Math.floor(Date.now() / 1000)) return null;
  return body;
}

function bearer(req) {
  const h = String(req.headers["authorization"] || "");
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : "";
}

/* ───────────────────────── 校验与限流 ───────────────────────── */

const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const MIN_PASSWORD = 6;
const MAX_PASSWORD = 64;

function badUsername(s) {
  return !USERNAME_RE.test(String(s || ""));
}

/* 单实例内的简易防爆破：同一用户名 10 分钟内最多 10 次失败 */
const FAILS = new Map();
const FAIL_WINDOW_MS = 10 * 60 * 1000;
const FAIL_LIMIT = 10;

function clientIp(req) {
  return (
    (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim() ||
    (req.socket && req.socket.remoteAddress) ||
    "unknown"
  );
}

function failKey(username, req) {
  return String(username || "").toLowerCase() + "|" + clientIp(req);
}

function tooManyFails(key) {
  const rec = FAILS.get(key);
  if (!rec) return false;
  if (Date.now() - rec.first > FAIL_WINDOW_MS) {
    FAILS.delete(key);
    return false;
  }
  return rec.count >= FAIL_LIMIT;
}

function noteFail(key) {
  const rec = FAILS.get(key);
  if (!rec || Date.now() - rec.first > FAIL_WINDOW_MS) {
    FAILS.set(key, { first: Date.now(), count: 1 });
    return;
  }
  rec.count += 1;
}

/* 注册入口的 IP 级限流：同一 IP 每小时最多 20 次注册尝试（单实例内计数，用于劝退脚本） */
const REG_ATTEMPTS = new Map();
const REG_WINDOW_MS = 60 * 60 * 1000;
const REG_LIMIT = 20;

function regTooMany(ip) {
  const rec = REG_ATTEMPTS.get(ip);
  if (!rec) return false;
  if (Date.now() - rec.first > REG_WINDOW_MS) {
    REG_ATTEMPTS.delete(ip);
    return false;
  }
  return rec.count >= REG_LIMIT;
}

function noteRegAttempt(ip) {
  const rec = REG_ATTEMPTS.get(ip);
  if (!rec || Date.now() - rec.first > REG_WINDOW_MS) {
    REG_ATTEMPTS.set(ip, { first: Date.now(), count: 1 });
    return;
  }
  rec.count += 1;
}

/* ───────────────────────── 业务处理 ───────────────────────── */

async function handleRegister(req, res) {
  const body = await readJson(req);
  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");
  const displayName = String(body.displayName || "").trim().slice(0, 24) || null;
  const inviteCode = normalizeInvite(body.invite || body.invite_code || "");

  if (badUsername(username)) {
    return sendJson(res, 400, { error: "bad_username", message: "用户名需为 3-20 位字母、数字或下划线" });
  }
  if (password.length < MIN_PASSWORD || password.length > MAX_PASSWORD) {
    return sendJson(res, 400, { error: "bad_password", message: "密码长度需为 6-64 位" });
  }
  if (!inviteCode) {
    return sendJson(res, 403, { error: "invite_required", message: "注册需要邀请码，请向发码的人索取" });
  }

  const ip = clientIp(req);
  if (regTooMany(ip)) {
    return sendJson(res, 429, { error: "too_many_attempts", message: "注册尝试过于频繁，请稍后再试" });
  }
  noteRegAttempt(ip);

  const failK = failKey(username, req);
  if (tooManyFails(failK)) {
    return sendJson(res, 429, { error: "too_many_attempts", message: "尝试过于频繁，请稍后再试" });
  }

  /* 先查重，避免为重复用户名白占一个邀请码名额 */
  const existed = await pgRequest(
    "GET",
    TABLES.accounts,
    "username=eq." + encodeURIComponent(username) + "&select=id&limit=1"
  );
  if (existed.ok && Array.isArray(existed.data) && existed.data.length > 0) {
    return sendJson(res, 409, { error: "username_taken", message: "这个用户名已经被注册了，换一个或直接登录" });
  }

  /* 先占名额再建账号，注册失败必须归还，否则会把别人的名额吃掉 */
  const claimed = await claimInvite(inviteCode);
  if (!claimed.ok) {
    return sendJson(res, claimed.status, claimed.body);
  }

  const created = await pgRequest(
    "POST",
    TABLES.accounts,
    "",
    {
      username: username,
      pass_hash: hashPassword(password),
      display_name: displayName,
      invite_code: inviteCode,
    },
    { Prefer: "return=representation" }
  );

  if (!created.ok) {
    await releaseInvite(inviteCode, claimed.next);
    const data = created.data || {};
    const isDuplicate =
      created.status === 409 ||
      String(data.code || "") === "23505" ||
      /duplicate key|already exists/i.test(
        String(data.message || "") + " " + String(data.details || "")
      );
    if (isDuplicate) {
      return sendJson(res, 409, { error: "username_taken", message: "这个用户名已经被注册了，换一个或直接登录" });
    }
    return sendJson(res, 502, { error: "db_failed", message: "注册失败，请稍后重试" });
  }

  const row = Array.isArray(created.data) ? created.data[0] : created.data;
  if (!row || !row.id) {
    await releaseInvite(inviteCode, claimed.next);
    return sendJson(res, 502, { error: "db_failed", message: "注册失败，请稍后重试" });
  }

  return sendJson(res, 200, {
    token: signToken(row),
    user: { username: row.username, displayName: row.display_name || "" },
  });
}

async function handleLogin(req, res) {
  const body = await readJson(req);
  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (badUsername(username) || !password) {
    return sendJson(res, 400, { error: "bad_credentials", message: "请输入用户名和密码" });
  }

  const failK = failKey(username, req);
  if (tooManyFails(failK)) {
    return sendJson(res, 429, { error: "too_many_attempts", message: "尝试过于频繁，请 10 分钟后再试" });
  }

  const found = await pgRequest(
    "GET",
    TABLES.accounts,
    "username=eq." + encodeURIComponent(username) + "&select=id,username,pass_hash,display_name&limit=1"
  );
  if (!found.ok) {
    return sendJson(res, 502, { error: "db_failed", message: "登录失败，请稍后重试" });
  }
  const row = Array.isArray(found.data) ? found.data[0] : null;
  if (!row || !verifyPassword(password, row.pass_hash)) {
    noteFail(failK);
    return sendJson(res, 401, { error: "bad_credentials", message: "用户名或密码不对" });
  }

  FAILS.delete(failK);
  pgRequest(
    "PATCH",
    TABLES.accounts,
    "id=eq." + encodeURIComponent(row.id),
    { last_login_at: new Date().toISOString() },
    { Prefer: "return=minimal" }
  ).catch(function () {
    /* 记录登录时间失败不影响登录 */
  });

  return sendJson(res, 200, {
    token: signToken(row),
    user: { username: row.username, displayName: row.display_name || "" },
  });
}

async function handleGetProgress(req, res, auth) {
  const found = await pgRequest(
    "GET",
    TABLES.progress,
    "account_id=eq." + encodeURIComponent(auth.uid) + "&select=payload,client_saved_at,updated_at&limit=1"
  );
  if (!found.ok) {
    return sendJson(res, 502, { error: "db_failed", message: "读取进度失败" });
  }
  const row = Array.isArray(found.data) ? found.data[0] : null;
  if (!row) return sendJson(res, 200, { payload: null, client_saved_at: 0, updated_at: null });
  return sendJson(res, 200, {
    payload: row.payload,
    client_saved_at: Number(row.client_saved_at) || 0,
    updated_at: row.updated_at || null,
  });
}

async function handlePutProgress(req, res, auth) {
  const body = await readJson(req);
  const payload = body.payload;
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.units)) {
    return sendJson(res, 400, { error: "bad_payload", message: "进度数据格式不对" });
  }
  const clientSavedAt = Number(body.client_saved_at) || Date.now();

  const saved = await pgRequest(
    "POST",
    TABLES.progress,
    "on_conflict=account_id",
    {
      account_id: Number(auth.uid),
      payload: payload,
      client_saved_at: clientSavedAt,
      updated_at: new Date().toISOString(),
    },
    { Prefer: "resolution=merge-duplicates,return=minimal" }
  );

  if (!saved.ok) {
    return sendJson(res, 502, { error: "db_failed", message: "保存失败，请稍后重试" });
  }
  return sendJson(res, 200, { ok: true, client_saved_at: clientSavedAt });
}

async function handleChangePassword(req, res, auth) {
  const body = await readJson(req);
  const oldPassword = String(body.old_password || "");
  const newPassword = String(body.new_password || "");

  if (!oldPassword) {
    return sendJson(res, 400, { error: "bad_password", message: "请输入原密码" });
  }
  if (newPassword.length < 6 || newPassword.length > 64) {
    return sendJson(res, 400, { error: "bad_password", message: "新密码需要 6-64 位" });
  }
  if (oldPassword === newPassword) {
    return sendJson(res, 400, { error: "bad_password", message: "新密码和原密码一样，无需修改" });
  }

  const failK = "chpwd|" + auth.uid + "|" + clientIp(req);
  if (tooManyFails(failK)) {
    return sendJson(res, 429, { error: "too_many_attempts", message: "尝试过于频繁，请 10 分钟后再试" });
  }

  const found = await pgRequest(
    "GET",
    TABLES.accounts,
    "id=eq." + encodeURIComponent(auth.uid) + "&select=id,pass_hash&limit=1"
  );
  if (!found.ok) {
    return sendJson(res, 502, { error: "db_failed", message: "修改失败，请稍后重试" });
  }
  const row = Array.isArray(found.data) ? found.data[0] : null;
  if (!row) {
    return sendJson(res, 401, { error: "unauthenticated", message: "账号不存在，请重新登录" });
  }
  if (!verifyPassword(oldPassword, row.pass_hash)) {
    noteFail(failK);
    return sendJson(res, 403, { error: "bad_password", message: "原密码不对" });
  }

  FAILS.delete(failK);
  const updated = await pgRequest(
    "PATCH",
    TABLES.accounts,
    "id=eq." + encodeURIComponent(row.id),
    { pass_hash: hashPassword(newPassword) },
    { Prefer: "return=minimal" }
  );
  if (!updated.ok) {
    return sendJson(res, 502, { error: "db_failed", message: "修改失败，请稍后重试" });
  }
  return sendJson(res, 200, { ok: true });
}

/* ───────────────────────── 路由 ───────────────────────── */

async function route(req, res) {
  const url = new URL(req.url, "http://localhost");
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = (req.method || "GET").toUpperCase();

  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (path === "/health") {
    return sendJson(res, 200, { ok: true, service: "ket-api", table: TABLES.accounts });
  }

  if (path === "/register") {
    if (method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" });
    return handleRegister(req, res);
  }

  if (path === "/login") {
    if (method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" });
    return handleLogin(req, res);
  }

  if (path === "/change-password") {
    if (method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" });
    const me = verifyToken(bearer(req));
    if (!me) return sendJson(res, 401, { error: "unauthenticated", message: "登录已过期，请重新登录" });
    return handleChangePassword(req, res, me);
  }

  if (path === "/progress") {
    const auth = verifyToken(bearer(req));
    if (!auth) return sendJson(res, 401, { error: "unauthenticated", message: "登录已过期，请重新登录" });
    if (method === "GET") return handleGetProgress(req, res, auth);
    if (method === "PUT" || method === "POST") return handlePutProgress(req, res, auth);
    return sendJson(res, 405, { error: "method_not_allowed" });
  }

  return sendJson(res, 404, { error: "not_found", path: path });
}

const server = http.createServer(function (req, res) {
  route(req, res).catch(function (err) {
    if (err && err.message === "body_too_large") {
      sendJson(res, 413, { error: "body_too_large", message: "数据太大了" });
      return;
    }
    if (err && err.message === "bad_json") {
      sendJson(res, 400, { error: "bad_json", message: "请求格式不对" });
      return;
    }
    console.error("[ket-api] unhandled", err && err.message);
    sendJson(res, 500, { error: "internal_error", message: "服务异常，请稍后重试" });
  });
});

server.listen(PORT, "0.0.0.0", function () {
  console.log("[ket-api] listening on " + PORT);
});

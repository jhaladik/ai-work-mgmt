var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// .wrangler/tmp/bundle-B7uNR5/checked-fetch.js
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
var urls;
var init_checked_fetch = __esm({
  ".wrangler/tmp/bundle-B7uNR5/checked-fetch.js"() {
    urls = /* @__PURE__ */ new Set();
    __name(checkURL, "checkURL");
    globalThis.fetch = new Proxy(globalThis.fetch, {
      apply(target, thisArg, argArray) {
        const [request, init] = argArray;
        checkURL(request, init);
        return Reflect.apply(target, thisArg, argArray);
      }
    });
  }
});

// wrangler-modules-watch:wrangler:modules-watch
var init_wrangler_modules_watch = __esm({
  "wrangler-modules-watch:wrangler:modules-watch"() {
    init_checked_fetch();
    init_modules_watch_stub();
  }
});

// ../../../AppData/Roaming/npm/node_modules/wrangler/templates/modules-watch-stub.js
var init_modules_watch_stub = __esm({
  "../../../AppData/Roaming/npm/node_modules/wrangler/templates/modules-watch-stub.js"() {
    init_wrangler_modules_watch();
  }
});

// src/utils/auth-utils.js
async function createJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = btoa(JSON.stringify(header));
  const encodedPayload = btoa(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1e3),
    exp: Math.floor(Date.now() / 1e3) + 24 * 60 * 60
    // 24 hours
  }));
  const data = `${encodedHeader}.${encodedPayload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${data}.${encodedSignature}`;
}
async function verifyJWT(token, secret) {
  try {
    const [header, payload, signature] = token.split(".");
    if (!header || !payload || !signature) {
      throw new Error("Invalid token format");
    }
    const data = `${header}.${payload}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const signatureBuffer = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify("HMAC", key, signatureBuffer, new TextEncoder().encode(data));
    if (!isValid) {
      throw new Error("Invalid signature");
    }
    const decodedPayload = JSON.parse(atob(payload));
    if (decodedPayload.exp < Math.floor(Date.now() / 1e3)) {
      throw new Error("Token expired");
    }
    return decodedPayload;
  } catch (error) {
    throw new Error(`Token verification failed: ${error.message}`);
  }
}
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + "salt_for_security");
  const hash = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}
async function verifyPassword(password, hash) {
  const hashedInput = await hashPassword(password);
  return hashedInput === hash;
}
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 255;
}
function isValidPassword(password) {
  return password && password.length >= 8 && password.length <= 128 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password);
}
function isValidRole(role) {
  return ["ceo", "manager", "employee"].includes(role);
}
function isValidName(name) {
  return name && name.length >= 2 && name.length <= 100 && /^[a-zA-Z\s]+$/.test(name);
}
async function authenticateRequest(request, env) {
  try {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return null;
    }
    const token = authHeader.replace("Bearer ", "");
    const payload = await verifyJWT(token, env.JWT_SECRET);
    return {
      userId: payload.userId,
      role: payload.role,
      organizationId: payload.organizationId,
      email: payload.email
    };
  } catch (error) {
    console.error("Authentication failed:", error.message);
    return null;
  }
}
async function recordGDPRConsent(userId, consentType, granted, request, env) {
  const ipAddress = request.headers.get("CF-Connecting-IP") || "unknown";
  const userAgent = request.headers.get("User-Agent") || "unknown";
  await env.DB.prepare(
    "INSERT INTO gdpr_consents (id, user_id, consent_type, granted, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(
    crypto.randomUUID(),
    userId,
    consentType,
    granted ? 1 : 0,
    ipAddress,
    userAgent
  ).run();
}
async function checkRateLimit(key, limit, window, env) {
  const current = await env.SESSIONS.get(`rate_limit:${key}`);
  const count = current ? parseInt(current) : 0;
  if (count >= limit) {
    return false;
  }
  await env.SESSIONS.put(`rate_limit:${key}`, (count + 1).toString(), {
    expirationTtl: window
  });
  return true;
}
var init_auth_utils = __esm({
  "src/utils/auth-utils.js"() {
    init_checked_fetch();
    init_modules_watch_stub();
    __name(createJWT, "createJWT");
    __name(verifyJWT, "verifyJWT");
    __name(hashPassword, "hashPassword");
    __name(verifyPassword, "verifyPassword");
    __name(isValidEmail, "isValidEmail");
    __name(isValidPassword, "isValidPassword");
    __name(isValidRole, "isValidRole");
    __name(isValidName, "isValidName");
    __name(authenticateRequest, "authenticateRequest");
    __name(recordGDPRConsent, "recordGDPRConsent");
    __name(checkRateLimit, "checkRateLimit");
  }
});

// src/utils/db-utils.js
function errorResponse(message, status = 400) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
function successResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
async function createUser(userData, env) {
  const userId = crypto.randomUUID();
  try {
    const result = await env.DB.prepare(
      `INSERT INTO users (id, organization_id, email, password_hash, name, role, skills, capacity_hours_per_week) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      userId,
      userData.organizationId,
      userData.email,
      userData.passwordHash,
      userData.name,
      userData.role,
      JSON.stringify(userData.skills || []),
      userData.capacityHours || 40
    ).run();
    return { success: true, userId, insertId: result.meta.last_row_id };
  } catch (error) {
    console.error("User creation failed:", error);
    throw new Error("Failed to create user");
  }
}
async function getUserByEmail(email, env) {
  try {
    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE email = ? AND is_active = 1"
    ).bind(email).first();
    if (user && user.skills) {
      user.skills = JSON.parse(user.skills);
    }
    return user;
  } catch (error) {
    console.error("Get user by email failed:", error);
    return null;
  }
}
async function getUserById(userId, env) {
  try {
    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE id = ? AND is_active = 1"
    ).bind(userId).first();
    if (user && user.skills) {
      user.skills = JSON.parse(user.skills);
    }
    return user;
  } catch (error) {
    console.error("Get user by ID failed:", error);
    return null;
  }
}
async function updateUserLastLogin(userId, env) {
  try {
    await env.DB.prepare(
      "UPDATE users SET last_login = ? WHERE id = ?"
    ).bind(Date.now(), userId).run();
  } catch (error) {
    console.error("Update last login failed:", error);
  }
}
async function createOrganization(orgData, env) {
  const orgId = crypto.randomUUID();
  try {
    await env.DB.prepare(
      "INSERT INTO organizations (id, name, settings) VALUES (?, ?, ?)"
    ).bind(
      orgId,
      orgData.name,
      JSON.stringify(orgData.settings || {})
    ).run();
    return { success: true, organizationId: orgId };
  } catch (error) {
    console.error("Organization creation failed:", error);
    throw new Error("Failed to create organization");
  }
}
async function createSession(userId, deviceInfo, request, env) {
  const sessionId = crypto.randomUUID();
  const sessionToken = crypto.randomUUID();
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1e3;
  try {
    await env.DB.prepare(
      `INSERT INTO user_sessions (id, user_id, session_token, device_info, ip_address, expires_at) 
         VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      sessionId,
      userId,
      sessionToken,
      deviceInfo,
      request.headers.get("CF-Connecting-IP") || "unknown",
      expiresAt
    ).run();
    return { sessionId, sessionToken };
  } catch (error) {
    console.error("Session creation failed:", error);
    return null;
  }
}
async function logAuditEvent(eventData, request, env) {
  try {
    await env.DB.prepare(
      `INSERT INTO audit_logs (id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, user_agent) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      crypto.randomUUID(),
      eventData.userId,
      eventData.organizationId,
      eventData.action,
      eventData.resourceType,
      eventData.resourceId,
      JSON.stringify(eventData.metadata || {}),
      request.headers.get("CF-Connecting-IP") || "unknown",
      request.headers.get("User-Agent") || "unknown"
    ).run();
  } catch (error) {
    console.error("Audit logging failed:", error);
  }
}
async function healthCheck(env) {
  try {
    const result = await env.DB.prepare("SELECT 1 as health").first();
    return result && result.health === 1;
  } catch (error) {
    console.error("Database health check failed:", error);
    return false;
  }
}
var init_db_utils = __esm({
  "src/utils/db-utils.js"() {
    init_checked_fetch();
    init_modules_watch_stub();
    __name(errorResponse, "errorResponse");
    __name(successResponse, "successResponse");
    __name(createUser, "createUser");
    __name(getUserByEmail, "getUserByEmail");
    __name(getUserById, "getUserById");
    __name(updateUserLastLogin, "updateUserLastLogin");
    __name(createOrganization, "createOrganization");
    __name(createSession, "createSession");
    __name(logAuditEvent, "logAuditEvent");
    __name(healthCheck, "healthCheck");
  }
});

// src/workers/auth-worker.js
var auth_worker_exports = {};
__export(auth_worker_exports, {
  default: () => auth_worker_default
});
async function handleRegister(request, env, ctx) {
  try {
    const { email, password, name, role, organizationName, gdprConsent } = await request.json();
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!await checkRateLimit(`register:${clientIP}`, 5, 3600, env)) {
      return errorResponse("Too many registration attempts. Try again in an hour.", 429);
    }
    if (!isValidEmail(email)) {
      return errorResponse("Invalid email format");
    }
    if (!isValidPassword(password)) {
      return errorResponse("Password must be 8+ characters with uppercase, lowercase, and number");
    }
    if (!isValidName(name)) {
      return errorResponse("Name must be 2-100 characters, letters and spaces only");
    }
    if (!isValidRole(role)) {
      return errorResponse("Invalid role. Must be: ceo, manager, or employee");
    }
    if (role === "ceo" && !organizationName) {
      return errorResponse("Organization name required for CEO role");
    }
    if (!gdprConsent) {
      return errorResponse("GDPR consent required");
    }
    const existingUser = await getUserByEmail(email, env);
    if (existingUser) {
      return errorResponse("User with this email already exists");
    }
    const passwordHash = await hashPassword(password);
    let organizationId = null;
    if (role === "ceo") {
      const orgResult = await createOrganization({ name: organizationName }, env);
      organizationId = orgResult.organizationId;
    } else {
      organizationId = "default-org";
    }
    const userResult = await createUser({
      organizationId,
      email,
      passwordHash,
      name,
      role
    }, env);
    const userId = userResult.userId;
    ctx.waitUntil(recordGDPRConsent(userId, "registration", true, request, env));
    const deviceInfo = request.headers.get("User-Agent") || "unknown";
    const session = await createSession(userId, deviceInfo, request, env);
    const token = await createJWT({
      userId,
      email,
      role,
      organizationId
    }, env.JWT_SECRET);
    await env.SESSIONS.put(`session:${userId}`, JSON.stringify({
      userId,
      email,
      role,
      organizationId,
      sessionToken: session.sessionToken,
      createdAt: Date.now()
    }), { expirationTtl: 86400 * 7 });
    ctx.waitUntil(logAuditEvent({
      userId,
      organizationId,
      action: "user_registered",
      resourceType: "user",
      resourceId: userId
    }, request, env));
    return successResponse({
      token,
      user: {
        id: userId,
        email,
        name,
        role,
        organizationId
      },
      message: "Registration successful"
    });
  } catch (error) {
    console.error("Registration failed:", error);
    return errorResponse("Registration failed");
  }
}
async function handleLogin(request, env, ctx) {
  try {
    const { email, password } = await request.json();
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!await checkRateLimit(`login:${clientIP}`, 10, 900, env)) {
      return errorResponse("Too many login attempts. Try again in 15 minutes.", 429);
    }
    if (!isValidEmail(email)) {
      return errorResponse("Invalid email format");
    }
    if (!password) {
      return errorResponse("Password required");
    }
    const user = await getUserByEmail(email, env);
    if (!user) {
      return errorResponse("Invalid credentials");
    }
    const passwordValid = await verifyPassword(password, user.password_hash);
    if (!passwordValid) {
      return errorResponse("Invalid credentials");
    }
    ctx.waitUntil(updateUserLastLogin(user.id, env));
    const deviceInfo = request.headers.get("User-Agent") || "unknown";
    const session = await createSession(user.id, deviceInfo, request, env);
    const token = await createJWT({
      userId: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organization_id
    }, env.JWT_SECRET);
    await env.SESSIONS.put(`session:${user.id}`, JSON.stringify({
      userId: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organization_id,
      sessionToken: session.sessionToken,
      createdAt: Date.now()
    }), { expirationTtl: 86400 * 7 });
    ctx.waitUntil(logAuditEvent({
      userId: user.id,
      organizationId: user.organization_id,
      action: "user_login",
      resourceType: "user",
      resourceId: user.id
    }, request, env));
    return successResponse({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        organizationId: user.organization_id,
        skills: user.skills
      },
      message: "Login successful"
    });
  } catch (error) {
    console.error("Login failed:", error);
    return errorResponse("Login failed");
  }
}
async function handleVerify(request, env) {
  try {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return errorResponse("Invalid or expired token", 401);
    }
    const userData = await getUserById(user.userId, env);
    if (!userData) {
      return errorResponse("User not found", 401);
    }
    return successResponse({
      valid: true,
      user: {
        id: userData.id,
        email: userData.email,
        name: userData.name,
        role: userData.role,
        organizationId: userData.organization_id,
        skills: userData.skills
      }
    });
  } catch (error) {
    console.error("Token verification failed:", error);
    return errorResponse("Token verification failed", 401);
  }
}
async function handleRefresh(request, env) {
  try {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return errorResponse("Invalid token", 401);
    }
    const newToken = await createJWT({
      userId: user.userId,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId
    }, env.JWT_SECRET);
    return successResponse({
      token: newToken,
      message: "Token refreshed"
    });
  } catch (error) {
    console.error("Token refresh failed:", error);
    return errorResponse("Token refresh failed");
  }
}
async function handleLogout(request, env, ctx) {
  try {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return successResponse({ message: "Logged out" });
    }
    ctx.waitUntil(env.SESSIONS.delete(`session:${user.userId}`));
    ctx.waitUntil(logAuditEvent({
      userId: user.userId,
      organizationId: user.organizationId,
      action: "user_logout",
      resourceType: "user",
      resourceId: user.userId
    }, request, env));
    return successResponse({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout failed:", error);
    return errorResponse("Logout failed");
  }
}
async function handleProfile(request, env) {
  try {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return errorResponse("Unauthorized", 401);
    }
    const userData = await getUserById(user.userId, env);
    if (!userData) {
      return errorResponse("User not found", 404);
    }
    return successResponse({
      id: userData.id,
      email: userData.email,
      name: userData.name,
      role: userData.role,
      organizationId: userData.organization_id,
      skills: userData.skills,
      capacityHours: userData.capacity_hours_per_week,
      calendarConnected: userData.calendar_connected === 1,
      lastLogin: userData.last_login
    });
  } catch (error) {
    console.error("Get profile failed:", error);
    return errorResponse("Failed to get profile");
  }
}
var auth_worker_default;
var init_auth_worker = __esm({
  "src/workers/auth-worker.js"() {
    init_checked_fetch();
    init_modules_watch_stub();
    init_auth_utils();
    init_db_utils();
    auth_worker_default = {
      async fetch(request, env, ctx) {
        const url = new URL(request.url);
        if (request.method === "OPTIONS") {
          return new Response(null, {
            headers: {
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE",
              "Access-Control-Allow-Headers": "Content-Type,Authorization",
              "Access-Control-Max-Age": "86400"
            }
          });
        }
        try {
          switch (url.pathname) {
            case "/api/auth/register":
              return handleRegister(request, env, ctx);
            case "/api/auth/login":
              return handleLogin(request, env, ctx);
            case "/api/auth/verify":
              return handleVerify(request, env);
            case "/api/auth/refresh":
              return handleRefresh(request, env);
            case "/api/auth/logout":
              return handleLogout(request, env, ctx);
            case "/api/auth/profile":
              return handleProfile(request, env);
            default:
              return errorResponse("Endpoint not found", 404);
          }
        } catch (error) {
          console.error("Auth worker error:", error);
          return errorResponse("Internal server error", 500);
        }
      }
    };
    __name(handleRegister, "handleRegister");
    __name(handleLogin, "handleLogin");
    __name(handleVerify, "handleVerify");
    __name(handleRefresh, "handleRefresh");
    __name(handleLogout, "handleLogout");
    __name(handleProfile, "handleProfile");
  }
});

// .wrangler/tmp/bundle-B7uNR5/middleware-loader.entry.ts
init_checked_fetch();
init_modules_watch_stub();

// .wrangler/tmp/bundle-B7uNR5/middleware-insertion-facade.js
init_checked_fetch();
init_modules_watch_stub();

// src/workers/api-worker.js
init_checked_fetch();
init_modules_watch_stub();
init_auth_utils();
init_db_utils();
var api_worker_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;
    if (method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,PATCH",
          "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Requested-With",
          "Access-Control-Max-Age": "86400"
        }
      });
    }
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,PATCH",
      "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Requested-With"
    };
    try {
      if (url.pathname === "/api/health") {
        return handleHealthCheck(env, corsHeaders);
      }
      if (url.pathname.startsWith("/api/auth/")) {
        return routeAuthRequest(request, env, ctx, corsHeaders);
      }
      const user = await authenticateRequest(request, env);
      if (!user && !isPublicRoute(url.pathname)) {
        return new Response(JSON.stringify({ error: "Authentication required" }), {
          status: 401,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      request.user = user;
      if (url.pathname.startsWith("/api/organizations/")) {
        return routeOrganizationRequest(request, env, ctx, corsHeaders);
      }
      if (url.pathname.startsWith("/api/users/")) {
        return routeUserRequest(request, env, ctx, corsHeaders);
      }
      return new Response(JSON.stringify({ error: "Endpoint not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    } catch (error) {
      console.error("API Worker error:", error);
      return new Response(JSON.stringify({
        error: "Internal server error",
        message: env.ENVIRONMENT === "development" ? error.message : void 0
      }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
  }
};
async function handleHealthCheck(env, corsHeaders) {
  try {
    const dbHealthy = await healthCheck(env);
    const status = dbHealthy ? 200 : 503;
    const healthData = {
      status: dbHealthy ? "healthy" : "unhealthy",
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      services: {
        database: dbHealthy ? "up" : "down",
        kv: "up",
        // KV is always available in Workers
        worker: "up"
      }
    };
    return new Response(JSON.stringify(healthData), {
      status,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      status: "error",
      error: error.message
    }), {
      status: 503,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  }
}
__name(handleHealthCheck, "handleHealthCheck");
async function routeAuthRequest(request, env, ctx, corsHeaders) {
  try {
    const authWorkerModule = await Promise.resolve().then(() => (init_auth_worker(), auth_worker_exports));
    const response = await authWorkerModule.default.fetch(request, env, ctx);
    const responseHeaders = new Headers(response.headers);
    Object.entries(corsHeaders).forEach(([key, value]) => {
      responseHeaders.set(key, value);
    });
    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });
  } catch (error) {
    console.error("Auth routing error:", error);
    return new Response(JSON.stringify({ error: "Authentication service unavailable" }), {
      status: 503,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  }
}
__name(routeAuthRequest, "routeAuthRequest");
async function routeOrganizationRequest(request, env, ctx, corsHeaders) {
  const url = new URL(request.url);
  const user = request.user;
  if (user.role === "employee") {
    return new Response(JSON.stringify({ error: "Insufficient permissions" }), {
      status: 403,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  }
  try {
    if (url.pathname === "/api/organizations/current" && request.method === "GET") {
      return getCurrentOrganization(user, env, corsHeaders);
    }
    if (url.pathname === "/api/organizations/users" && request.method === "GET") {
      return getOrganizationUsers(user, env, corsHeaders);
    }
    return new Response(JSON.stringify({ error: "Organization endpoint not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  } catch (error) {
    console.error("Organization routing error:", error);
    return new Response(JSON.stringify({ error: "Organization service error" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  }
}
__name(routeOrganizationRequest, "routeOrganizationRequest");
async function routeUserRequest(request, env, ctx, corsHeaders) {
  const url = new URL(request.url);
  const user = request.user;
  try {
    if (url.pathname === "/api/users/me" && request.method === "GET") {
      return getUserProfile(user, env, corsHeaders);
    }
    if (url.pathname === "/api/users/me" && request.method === "PUT") {
      return updateUserProfile(request, user, env, corsHeaders);
    }
    return new Response(JSON.stringify({ error: "User endpoint not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  } catch (error) {
    console.error("User routing error:", error);
    return new Response(JSON.stringify({ error: "User service error" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  }
}
__name(routeUserRequest, "routeUserRequest");
async function getCurrentOrganization(user, env, corsHeaders) {
  try {
    const org = await env.DB.prepare(
      "SELECT id, name, settings, created_at FROM organizations WHERE id = ?"
    ).bind(user.organizationId).first();
    if (!org) {
      return new Response(JSON.stringify({ error: "Organization not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
    const userCount = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM users WHERE organization_id = ? AND is_active = 1"
    ).bind(user.organizationId).first();
    return new Response(JSON.stringify({
      id: org.id,
      name: org.name,
      settings: JSON.parse(org.settings || "{}"),
      userCount: userCount.count,
      createdAt: org.created_at
    }), {
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  } catch (error) {
    console.error("Get organization error:", error);
    return new Response(JSON.stringify({ error: "Failed to get organization" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  }
}
__name(getCurrentOrganization, "getCurrentOrganization");
async function getOrganizationUsers(user, env, corsHeaders) {
  try {
    const users = await env.DB.prepare(
      `SELECT id, email, name, role, skills, capacity_hours_per_week, 
              calendar_connected, last_login, created_at 
       FROM users 
       WHERE organization_id = ? AND is_active = 1
       ORDER BY created_at DESC`
    ).bind(user.organizationId).all();
    const usersWithSkills = users.results.map((u) => ({
      ...u,
      skills: JSON.parse(u.skills || "[]"),
      calendarConnected: u.calendar_connected === 1
    }));
    return new Response(JSON.stringify({
      users: usersWithSkills,
      total: usersWithSkills.length
    }), {
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  } catch (error) {
    console.error("Get organization users error:", error);
    return new Response(JSON.stringify({ error: "Failed to get users" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  }
}
__name(getOrganizationUsers, "getOrganizationUsers");
async function getUserProfile(user, env, corsHeaders) {
  try {
    const userData = await env.DB.prepare(
      `SELECT id, email, name, role, skills, capacity_hours_per_week, 
              calendar_connected, calendar_provider, last_login, created_at
       FROM users WHERE id = ?`
    ).bind(user.userId).first();
    if (!userData) {
      return new Response(JSON.stringify({ error: "User not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
    return new Response(JSON.stringify({
      id: userData.id,
      email: userData.email,
      name: userData.name,
      role: userData.role,
      skills: JSON.parse(userData.skills || "[]"),
      capacityHours: userData.capacity_hours_per_week,
      calendarConnected: userData.calendar_connected === 1,
      calendarProvider: userData.calendar_provider,
      lastLogin: userData.last_login,
      createdAt: userData.created_at
    }), {
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  } catch (error) {
    console.error("Get user profile error:", error);
    return new Response(JSON.stringify({ error: "Failed to get profile" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  }
}
__name(getUserProfile, "getUserProfile");
async function updateUserProfile(request, user, env, corsHeaders) {
  try {
    const { name, skills, capacityHours } = await request.json();
    if (name && (name.length < 2 || name.length > 100)) {
      return new Response(JSON.stringify({ error: "Name must be 2-100 characters" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
    if (capacityHours && (capacityHours < 1 || capacityHours > 80)) {
      return new Response(JSON.stringify({ error: "Capacity hours must be 1-80" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
    const updates = [];
    const params = [];
    if (name) {
      updates.push("name = ?");
      params.push(name);
    }
    if (skills) {
      updates.push("skills = ?");
      params.push(JSON.stringify(skills));
    }
    if (capacityHours) {
      updates.push("capacity_hours_per_week = ?");
      params.push(capacityHours);
    }
    updates.push("updated_at = ?");
    params.push(Date.now());
    params.push(user.userId);
    await env.DB.prepare(
      `UPDATE users SET ${updates.join(", ")} WHERE id = ?`
    ).bind(...params).run();
    return new Response(JSON.stringify({ message: "Profile updated successfully" }), {
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  } catch (error) {
    console.error("Update user profile error:", error);
    return new Response(JSON.stringify({ error: "Failed to update profile" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders }
    });
  }
}
__name(updateUserProfile, "updateUserProfile");
function isPublicRoute(pathname) {
  const publicRoutes = [
    "/api/health",
    "/api/auth/register",
    "/api/auth/login"
  ];
  return publicRoutes.includes(pathname);
}
__name(isPublicRoute, "isPublicRoute");

// ../../../AppData/Roaming/npm/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
init_checked_fetch();
init_modules_watch_stub();
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../../AppData/Roaming/npm/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
init_checked_fetch();
init_modules_watch_stub();
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-B7uNR5/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = api_worker_default;

// ../../../AppData/Roaming/npm/node_modules/wrangler/templates/middleware/common.ts
init_checked_fetch();
init_modules_watch_stub();
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-B7uNR5/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=api-worker.js.map

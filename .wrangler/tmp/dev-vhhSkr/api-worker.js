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

// .wrangler/tmp/bundle-YxKzlX/checked-fetch.js
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
  ".wrangler/tmp/bundle-YxKzlX/checked-fetch.js"() {
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
var init_auth_utils = __esm({
  "src/utils/auth-utils.js"() {
    init_checked_fetch();
    init_modules_watch_stub();
    __name(verifyJWT, "verifyJWT");
    __name(authenticateRequest, "authenticateRequest");
  }
});

// src/utils/db-utils.js
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
    __name(healthCheck, "healthCheck");
  }
});

// src/workers/auth-worker.js
var auth_worker_exports = {};
__export(auth_worker_exports, {
  default: () => auth_worker_default
});
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
function isPublicRoute(pathname) {
  const publicRoutes = [
    "/api/health",
    "/api/auth/register",
    "/api/auth/login"
  ];
  return publicRoutes.includes(pathname);
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
    __name(handleHealthCheck, "handleHealthCheck");
    __name(routeAuthRequest, "routeAuthRequest");
    __name(routeOrganizationRequest, "routeOrganizationRequest");
    __name(routeUserRequest, "routeUserRequest");
    __name(getCurrentOrganization, "getCurrentOrganization");
    __name(getOrganizationUsers, "getOrganizationUsers");
    __name(getUserProfile, "getUserProfile");
    __name(updateUserProfile, "updateUserProfile");
    __name(isPublicRoute, "isPublicRoute");
  }
});

// .wrangler/tmp/bundle-YxKzlX/middleware-loader.entry.ts
init_checked_fetch();
init_modules_watch_stub();

// .wrangler/tmp/bundle-YxKzlX/middleware-insertion-facade.js
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
        return handleHealthCheck2(env, corsHeaders);
      }
      if (url.pathname.startsWith("/api/auth/")) {
        return routeAuthRequest2(request, env, ctx, corsHeaders);
      }
      const user = await authenticateRequest(request, env);
      if (!user && !isPublicRoute2(url.pathname)) {
        return new Response(JSON.stringify({ error: "Authentication required" }), {
          status: 401,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      request.user = user;
      if (url.pathname.startsWith("/api/organizations/")) {
        return routeOrganizationRequest2(request, env, ctx, corsHeaders);
      }
      if (url.pathname.startsWith("/api/users/")) {
        return routeUserRequest2(request, env, ctx, corsHeaders);
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
async function handleHealthCheck2(env, corsHeaders) {
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
__name(handleHealthCheck2, "handleHealthCheck");
async function routeAuthRequest2(request, env, ctx, corsHeaders) {
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
__name(routeAuthRequest2, "routeAuthRequest");
async function routeOrganizationRequest2(request, env, ctx, corsHeaders) {
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
      return getCurrentOrganization2(user, env, corsHeaders);
    }
    if (url.pathname === "/api/organizations/users" && request.method === "GET") {
      return getOrganizationUsers2(user, env, corsHeaders);
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
__name(routeOrganizationRequest2, "routeOrganizationRequest");
async function routeUserRequest2(request, env, ctx, corsHeaders) {
  const url = new URL(request.url);
  const user = request.user;
  try {
    if (url.pathname === "/api/users/me" && request.method === "GET") {
      return getUserProfile2(user, env, corsHeaders);
    }
    if (url.pathname === "/api/users/me" && request.method === "PUT") {
      return updateUserProfile2(request, user, env, corsHeaders);
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
__name(routeUserRequest2, "routeUserRequest");
async function getCurrentOrganization2(user, env, corsHeaders) {
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
__name(getCurrentOrganization2, "getCurrentOrganization");
async function getOrganizationUsers2(user, env, corsHeaders) {
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
__name(getOrganizationUsers2, "getOrganizationUsers");
async function getUserProfile2(user, env, corsHeaders) {
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
__name(getUserProfile2, "getUserProfile");
async function updateUserProfile2(request, user, env, corsHeaders) {
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
__name(updateUserProfile2, "updateUserProfile");
function isPublicRoute2(pathname) {
  const publicRoutes = [
    "/api/health",
    "/api/auth/register",
    "/api/auth/login"
  ];
  return publicRoutes.includes(pathname);
}
__name(isPublicRoute2, "isPublicRoute");

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

// .wrangler/tmp/bundle-YxKzlX/middleware-insertion-facade.js
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

// .wrangler/tmp/bundle-YxKzlX/middleware-loader.entry.ts
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

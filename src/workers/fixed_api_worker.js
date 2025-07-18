// Main API Worker for AI Work Management System
// Routes requests to appropriate handlers and provides middleware

import { authenticateRequest } from '../utils/auth-utils.js';
import { errorResponse, successResponse, healthCheck } from '../utils/db-utils.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;
    
    // CORS handling for all requests
    if (method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,PATCH',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Requested-With',
          'Access-Control-Max-Age': '86400'
        }
      });
    }
    
    // Add CORS headers to all responses
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,PATCH',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Requested-With'
    };
    
    try {
      // Health check endpoint
      if (url.pathname === '/api/health') {
        return handleHealthCheck(env, corsHeaders);
      }
      
      // Authentication routes
      if (url.pathname.startsWith('/api/auth/')) {
        return routeAuthRequest(request, env, ctx, corsHeaders);
      }
      
      // Protected routes require authentication
      const user = await authenticateRequest(request, env);
      if (!user && !isPublicRoute(url.pathname)) {
        return new Response(JSON.stringify({ error: 'Authentication required' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      // Attach user to request for convenience
      request.user = user;
      
      // Route to appropriate handlers
      if (url.pathname.startsWith('/api/organizations/')) {
        return routeOrganizationRequest(request, env, ctx, corsHeaders);
      }
      
      if (url.pathname.startsWith('/api/users/')) {
        return routeUserRequest(request, env, ctx, corsHeaders);
      }
      
      // Default 404 for unmatched routes
      return new Response(JSON.stringify({ error: 'Endpoint not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
      
    } catch (error) {
      console.error('API Worker error:', error);
      return new Response(JSON.stringify({ 
        error: 'Internal server error',
        message: env.ENVIRONMENT === 'development' ? error.message : undefined
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};

async function handleHealthCheck(env, corsHeaders) {
  try {
    const dbHealthy = await healthCheck(env);
    const status = dbHealthy ? 200 : 503;
    
    const healthData = {
      status: dbHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      services: {
        database: dbHealthy ? 'up' : 'down',
        kv: 'up', // KV is always available in Workers
        worker: 'up'
      }
    };
    
    return new Response(JSON.stringify(healthData), {
      status,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      status: 'error',
      error: error.message
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function routeAuthRequest(request, env, ctx, corsHeaders) {
  // Import auth worker (in real deployment, this would be a separate worker)
  try {
    const authWorkerModule = await import('./auth-worker.js');
    const response = await authWorkerModule.default.fetch(request, env, ctx);
    
    // Add CORS headers to auth responses
    const responseHeaders = new Headers(response.headers);
    Object.entries(corsHeaders).forEach(([key, value]) => {
      responseHeaders.set(key, value);
    });
    
    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });
  } catch (error) {
    console.error('Auth routing error:', error);
    return new Response(JSON.stringify({ error: 'Authentication service unavailable' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function routeOrganizationRequest(request, env, ctx, corsHeaders) {
  const url = new URL(request.url);
  const user = request.user;
  
  // Only CEOs and managers can access organization endpoints
  if (user.role === 'employee') {
    return new Response(JSON.stringify({ error: 'Insufficient permissions' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  try {
    if (url.pathname === '/api/organizations/current' && request.method === 'GET') {
      return getCurrentOrganization(user, env, corsHeaders);
    }
    
    if (url.pathname === '/api/organizations/users' && request.method === 'GET') {
      return getOrganizationUsers(user, env, corsHeaders);
    }
    
    return new Response(JSON.stringify({ error: 'Organization endpoint not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('Organization routing error:', error);
    return new Response(JSON.stringify({ error: 'Organization service error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function routeUserRequest(request, env, ctx, corsHeaders) {
  const url = new URL(request.url);
  const user = request.user;
  
  try {
    if (url.pathname === '/api/users/me' && request.method === 'GET') {
      return getUserProfile(user, env, corsHeaders);
    }
    
    if (url.pathname === '/api/users/me' && request.method === 'PUT') {
      return updateUserProfile(request, user, env, corsHeaders);
    }
    
    return new Response(JSON.stringify({ error: 'User endpoint not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('User routing error:', error);
    return new Response(JSON.stringify({ error: 'User service error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function getCurrentOrganization(user, env, corsHeaders) {
  try {
    const org = await env.DB.prepare(
      'SELECT id, name, settings, created_at FROM organizations WHERE id = ?'
    ).bind(user.organizationId).first();
    
    if (!org) {
      return new Response(JSON.stringify({ error: 'Organization not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    const userCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM users WHERE organization_id = ? AND is_active = 1'
    ).bind(user.organizationId).first();
    
    return new Response(JSON.stringify({
      id: org.id,
      name: org.name,
      settings: JSON.parse(org.settings || '{}'),
      userCount: userCount.count,
      createdAt: org.created_at
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('Get organization error:', error);
    return new Response(JSON.stringify({ error: 'Failed to get organization' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
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
    
    const usersWithSkills = users.results.map(u => ({
      ...u,
      skills: JSON.parse(u.skills || '[]'),
      calendarConnected: u.calendar_connected === 1
    }));
    
    return new Response(JSON.stringify({
      users: usersWithSkills,
      total: usersWithSkills.length
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('Get organization users error:', error);
    return new Response(JSON.stringify({ error: 'Failed to get users' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
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
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    return new Response(JSON.stringify({
      id: userData.id,
      email: userData.email,
      name: userData.name,
      role: userData.role,
      skills: JSON.parse(userData.skills || '[]'),
      capacityHours: userData.capacity_hours_per_week,
      calendarConnected: userData.calendar_connected === 1,
      calendarProvider: userData.calendar_provider,
      lastLogin: userData.last_login,
      createdAt: userData.created_at
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('Get user profile error:', error);
    return new Response(JSON.stringify({ error: 'Failed to get profile' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function updateUserProfile(request, user, env, corsHeaders) {
  try {
    const { name, skills, capacityHours } = await request.json();
    
    // Validate input
    if (name && (name.length < 2 || name.length > 100)) {
      return new Response(JSON.stringify({ error: 'Name must be 2-100 characters' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    if (capacityHours && (capacityHours < 1 || capacityHours > 80)) {
      return new Response(JSON.stringify({ error: 'Capacity hours must be 1-80' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    // Update user
    const updates = [];
    const params = [];
    
    if (name) {
      updates.push('name = ?');
      params.push(name);
    }
    
    if (skills) {
      updates.push('skills = ?');
      params.push(JSON.stringify(skills));
    }
    
    if (capacityHours) {
      updates.push('capacity_hours_per_week = ?');
      params.push(capacityHours);
    }
    
    updates.push('updated_at = ?');
    params.push(Date.now());
    params.push(user.userId);
    
    await env.DB.prepare(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`
    ).bind(...params).run();
    
    return new Response(JSON.stringify({ message: 'Profile updated successfully' }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('Update user profile error:', error);
    return new Response(JSON.stringify({ error: 'Failed to update profile' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

function isPublicRoute(pathname) {
  const publicRoutes = [
    '/api/health',
    '/api/auth/register',
    '/api/auth/login'
  ];
  
  return publicRoutes.includes(pathname);
}
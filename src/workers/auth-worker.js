// Authentication Worker for AI Work Management System
// Handles user registration, login, and JWT verification

import { 
  createJWT, verifyJWT, hashPassword, verifyPassword, 
  isValidEmail, isValidPassword, isValidRole, isValidName,
  authenticateRequest, recordGDPRConsent, checkRateLimit
} from '../utils/auth-utils.js';

import {
  createUser, getUserByEmail, getUserById, updateUserLastLogin,
  createOrganization, createSession, logAuditEvent,
  errorResponse, successResponse
} from '../utils/db-utils.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // CORS handling
    if (request.method === 'OPTIONS') {
      return new Response(null, { 
        headers: { 
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization',
          'Access-Control-Max-Age': '86400'
        } 
      });
    }
    
    try {
      switch (url.pathname) {
        case '/api/auth/register':
          return handleRegister(request, env, ctx);
        case '/api/auth/login':
          return handleLogin(request, env, ctx);
        case '/api/auth/verify':
          return handleVerify(request, env);
        case '/api/auth/refresh':
          return handleRefresh(request, env);
        case '/api/auth/logout':
          return handleLogout(request, env, ctx);
        case '/api/auth/profile':
          return handleProfile(request, env);
        default:
          return errorResponse('Endpoint not found', 404);
      }
    } catch (error) {
      console.error('Auth worker error:', error);
      return errorResponse('Internal server error', 500);
    }
  }
};

async function handleRegister(request, env, ctx) {
  try {
    const { email, password, name, role, organizationName, gdprConsent } = await request.json();
    
    // Rate limiting
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!await checkRateLimit(`register:${clientIP}`, 5, 3600, env)) {
      return errorResponse('Too many registration attempts. Try again in an hour.', 429);
    }
    
    // Input validation
    if (!isValidEmail(email)) {
      return errorResponse('Invalid email format');
    }
    
    if (!isValidPassword(password)) {
      return errorResponse('Password must be 8+ characters with uppercase, lowercase, and number');
    }
    
    if (!isValidName(name)) {
      return errorResponse('Name must be 2-100 characters, letters and spaces only');
    }
    
    if (!isValidRole(role)) {
      return errorResponse('Invalid role. Must be: ceo, manager, or employee');
    }
    
    if (role === 'ceo' && !organizationName) {
      return errorResponse('Organization name required for CEO role');
    }
    
    if (!gdprConsent) {
      return errorResponse('GDPR consent required');
    }
    
    // Check if user already exists
    const existingUser = await getUserByEmail(email, env);
    if (existingUser) {
      return errorResponse('User with this email already exists');
    }
    
    // Hash password
    const passwordHash = await hashPassword(password);
    
    // Create organization if CEO
    let organizationId = null;
    if (role === 'ceo') {
      const orgResult = await createOrganization({ name: organizationName }, env);
      organizationId = orgResult.organizationId;
    } else {
      // For now, assign to default org (in real app, this would be invitation-based)
      organizationId = 'default-org';
    }
    
    // Create user
    const userResult = await createUser({
      organizationId,
      email,
      passwordHash,
      name,
      role
    }, env);
    
    const userId = userResult.userId;
    
    // Record GDPR consent
    ctx.waitUntil(recordGDPRConsent(userId, 'registration', true, request, env));
    
    // Create session
    const deviceInfo = request.headers.get('User-Agent') || 'unknown';
    const session = await createSession(userId, deviceInfo, request, env);
    
    // Create JWT token
    const token = await createJWT({
      userId,
      email,
      role,
      organizationId
    }, env.JWT_SECRET);
    
    // Store session in KV for quick access
    await env.SESSIONS.put(`session:${userId}`, JSON.stringify({
      userId,
      email,
      role,
      organizationId,
      sessionToken: session.sessionToken,
      createdAt: Date.now()
    }), { expirationTtl: 86400 * 7 }); // 7 days
    
    // Log audit event
    ctx.waitUntil(logAuditEvent({
      userId,
      organizationId,
      action: 'user_registered',
      resourceType: 'user',
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
      message: 'Registration successful'
    });
    
  } catch (error) {
    console.error('Registration failed:', error);
    return errorResponse('Registration failed');
  }
}

async function handleLogin(request, env, ctx) {
  try {
    const { email, password } = await request.json();
    
    // Rate limiting
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!await checkRateLimit(`login:${clientIP}`, 10, 900, env)) {
      return errorResponse('Too many login attempts. Try again in 15 minutes.', 429);
    }
    
    // Input validation
    if (!isValidEmail(email)) {
      return errorResponse('Invalid email format');
    }
    
    if (!password) {
      return errorResponse('Password required');
    }
    
    // Get user
    const user = await getUserByEmail(email, env);
    if (!user) {
      return errorResponse('Invalid credentials');
    }
    
    // Verify password
    const passwordValid = await verifyPassword(password, user.password_hash);
    if (!passwordValid) {
      return errorResponse('Invalid credentials');
    }
    
    // Update last login
    ctx.waitUntil(updateUserLastLogin(user.id, env));
    
    // Create session
    const deviceInfo = request.headers.get('User-Agent') || 'unknown';
    const session = await createSession(user.id, deviceInfo, request, env);
    
    // Create JWT token
    const token = await createJWT({
      userId: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organization_id
    }, env.JWT_SECRET);
    
    // Store session in KV
    await env.SESSIONS.put(`session:${user.id}`, JSON.stringify({
      userId: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organization_id,
      sessionToken: session.sessionToken,
      createdAt: Date.now()
    }), { expirationTtl: 86400 * 7 });
    
    // Log audit event
    ctx.waitUntil(logAuditEvent({
      userId: user.id,
      organizationId: user.organization_id,
      action: 'user_login',
      resourceType: 'user',
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
      message: 'Login successful'
    });
    
  } catch (error) {
    console.error('Login failed:', error);
    return errorResponse('Login failed');
  }
}

async function handleVerify(request, env) {
  try {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return errorResponse('Invalid or expired token', 401);
    }
    
    // Get fresh user data
    const userData = await getUserById(user.userId, env);
    if (!userData) {
      return errorResponse('User not found', 401);
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
    console.error('Token verification failed:', error);
    return errorResponse('Token verification failed', 401);
  }
}

async function handleRefresh(request, env) {
  try {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return errorResponse('Invalid token', 401);
    }
    
    // Create new token
    const newToken = await createJWT({
      userId: user.userId,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId
    }, env.JWT_SECRET);
    
    return successResponse({
      token: newToken,
      message: 'Token refreshed'
    });
    
  } catch (error) {
    console.error('Token refresh failed:', error);
    return errorResponse('Token refresh failed');
  }
}

async function handleLogout(request, env, ctx) {
  try {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return successResponse({ message: 'Logged out' });
    }
    
    // Remove session from KV
    ctx.waitUntil(env.SESSIONS.delete(`session:${user.userId}`));
    
    // Log audit event
    ctx.waitUntil(logAuditEvent({
      userId: user.userId,
      organizationId: user.organizationId,
      action: 'user_logout',
      resourceType: 'user',
      resourceId: user.userId
    }, request, env));
    
    return successResponse({ message: 'Logged out successfully' });
    
  } catch (error) {
    console.error('Logout failed:', error);
    return errorResponse('Logout failed');
  }
}

async function handleProfile(request, env) {
  try {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return errorResponse('Unauthorized', 401);
    }
    
    const userData = await getUserById(user.userId, env);
    if (!userData) {
      return errorResponse('User not found', 404);
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
    console.error('Get profile failed:', error);
    return errorResponse('Failed to get profile');
  }
}
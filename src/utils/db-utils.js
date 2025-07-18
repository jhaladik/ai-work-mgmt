// Database utilities for AI Work Management System
// Common D1 database operations and helpers

// Error response helper
export function errorResponse(message, status = 400) {
    return new Response(JSON.stringify({ error: message }), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // Success response helper
  export function successResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // User operations
  export async function createUser(userData, env) {
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
      console.error('User creation failed:', error);
      throw new Error('Failed to create user');
    }
  }
  
  export async function getUserByEmail(email, env) {
    try {
      const user = await env.DB.prepare(
        'SELECT * FROM users WHERE email = ? AND is_active = 1'
      ).bind(email).first();
      
      if (user && user.skills) {
        user.skills = JSON.parse(user.skills);
      }
      
      return user;
    } catch (error) {
      console.error('Get user by email failed:', error);
      return null;
    }
  }
  
  export async function getUserById(userId, env) {
    try {
      const user = await env.DB.prepare(
        'SELECT * FROM users WHERE id = ? AND is_active = 1'
      ).bind(userId).first();
      
      if (user && user.skills) {
        user.skills = JSON.parse(user.skills);
      }
      
      return user;
    } catch (error) {
      console.error('Get user by ID failed:', error);
      return null;
    }
  }
  
  export async function updateUserLastLogin(userId, env) {
    try {
      await env.DB.prepare(
        'UPDATE users SET last_login = ? WHERE id = ?'
      ).bind(Date.now(), userId).run();
    } catch (error) {
      console.error('Update last login failed:', error);
    }
  }
  
  // Organization operations
  export async function createOrganization(orgData, env) {
    const orgId = crypto.randomUUID();
    
    try {
      await env.DB.prepare(
        'INSERT INTO organizations (id, name, settings) VALUES (?, ?, ?)'
      ).bind(
        orgId,
        orgData.name,
        JSON.stringify(orgData.settings || {})
      ).run();
      
      return { success: true, organizationId: orgId };
    } catch (error) {
      console.error('Organization creation failed:', error);
      throw new Error('Failed to create organization');
    }
  }
  
  export async function getOrganizationById(orgId, env) {
    try {
      const org = await env.DB.prepare(
        'SELECT * FROM organizations WHERE id = ?'
      ).bind(orgId).first();
      
      if (org && org.settings) {
        org.settings = JSON.parse(org.settings);
      }
      
      return org;
    } catch (error) {
      console.error('Get organization failed:', error);
      return null;
    }
  }
  
  // Session management
  export async function createSession(userId, deviceInfo, request, env) {
    const sessionId = crypto.randomUUID();
    const sessionToken = crypto.randomUUID();
    const expiresAt = Date.now() + (7 * 24 * 60 * 60 * 1000); // 7 days
    
    try {
      await env.DB.prepare(
        `INSERT INTO user_sessions (id, user_id, session_token, device_info, ip_address, expires_at) 
         VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(
        sessionId,
        userId,
        sessionToken,
        deviceInfo,
        request.headers.get('CF-Connecting-IP') || 'unknown',
        expiresAt
      ).run();
      
      return { sessionId, sessionToken };
    } catch (error) {
      console.error('Session creation failed:', error);
      return null;
    }
  }
  
  export async function validateSession(sessionToken, env) {
    try {
      const session = await env.DB.prepare(
        `SELECT s.*, u.id as user_id, u.role, u.organization_id 
         FROM user_sessions s 
         JOIN users u ON s.user_id = u.id 
         WHERE s.session_token = ? AND s.expires_at > ? AND u.is_active = 1`
      ).bind(sessionToken, Date.now()).first();
      
      if (session) {
        // Update last activity
        await env.DB.prepare(
          'UPDATE user_sessions SET last_activity = ? WHERE id = ?'
        ).bind(Date.now(), session.id).run();
      }
      
      return session;
    } catch (error) {
      console.error('Session validation failed:', error);
      return null;
    }
  }
  
  // Audit logging
  export async function logAuditEvent(eventData, request, env) {
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
        request.headers.get('CF-Connecting-IP') || 'unknown',
        request.headers.get('User-Agent') || 'unknown'
      ).run();
    } catch (error) {
      console.error('Audit logging failed:', error);
    }
  }
  
  // Database health check
  export async function healthCheck(env) {
    try {
      const result = await env.DB.prepare('SELECT 1 as health').first();
      return result && result.health === 1;
    } catch (error) {
      console.error('Database health check failed:', error);
      return false;
    }
  }
  
  // Clean up expired sessions
  export async function cleanupExpiredSessions(env) {
    try {
      const result = await env.DB.prepare(
        'DELETE FROM user_sessions WHERE expires_at < ?'
      ).bind(Date.now()).run();
      
      console.log(`Cleaned up ${result.meta.changes} expired sessions`);
      return result.meta.changes;
    } catch (error) {
      console.error('Session cleanup failed:', error);
      return 0;
    }
  }
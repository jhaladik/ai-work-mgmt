// Auth utilities for AI Work Management System
// JWT helpers, password hashing, and validation

// JWT token creation and verification
export async function createJWT(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    
    const encodedHeader = btoa(JSON.stringify(header));
    const encodedPayload = btoa(JSON.stringify({
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
    }));
    
    const data = `${encodedHeader}.${encodedPayload}`;
    
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)));
    
    return `${data}.${encodedSignature}`;
  }
  
  export async function verifyJWT(token, secret) {
    try {
      const [header, payload, signature] = token.split('.');
      
      if (!header || !payload || !signature) {
        throw new Error('Invalid token format');
      }
      
      const data = `${header}.${payload}`;
      
      const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      );
      
      const signatureBuffer = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
      const isValid = await crypto.subtle.verify('HMAC', key, signatureBuffer, new TextEncoder().encode(data));
      
      if (!isValid) {
        throw new Error('Invalid signature');
      }
      
      const decodedPayload = JSON.parse(atob(payload));
      
      // Check expiration
      if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error('Token expired');
      }
      
      return decodedPayload;
    } catch (error) {
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }
  
  // Password hashing and verification
  export async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + 'salt_for_security');
    const hash = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  }
  
  export async function verifyPassword(password, hash) {
    const hashedInput = await hashPassword(password);
    return hashedInput === hash;
  }
  
  // Input validation
  export function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 255;
  }
  
  export function isValidPassword(password) {
    return password && 
           password.length >= 8 && 
           password.length <= 128 &&
           /[A-Z]/.test(password) && 
           /[a-z]/.test(password) &&
           /[0-9]/.test(password);
  }
  
  export function isValidRole(role) {
    return ['ceo', 'manager', 'employee'].includes(role);
  }
  
  export function isValidName(name) {
    return name && name.length >= 2 && name.length <= 100 && /^[a-zA-Z\s]+$/.test(name);
  }
  
  // User authentication middleware
  export async function authenticateRequest(request, env) {
    try {
      const authHeader = request.headers.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
      }
      
      const token = authHeader.replace('Bearer ', '');
      const payload = await verifyJWT(token, env.JWT_SECRET);
      
      // Add user info to request for convenience
      return {
        userId: payload.userId,
        role: payload.role,
        organizationId: payload.organizationId,
        email: payload.email
      };
    } catch (error) {
      console.error('Authentication failed:', error.message);
      return null;
    }
  }
  
  // GDPR consent recording
  export async function recordGDPRConsent(userId, consentType, granted, request, env) {
    const ipAddress = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';
    
    await env.DB.prepare(
      'INSERT INTO gdpr_consents (id, user_id, consent_type, granted, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(
      crypto.randomUUID(),
      userId,
      consentType,
      granted ? 1 : 0,
      ipAddress,
      userAgent
    ).run();
  }
  
  // Generate secure random token
  export function generateSecureToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array)).replace(/[+/=]/g, '');
  }
  
  // Rate limiting helper
  export async function checkRateLimit(key, limit, window, env) {
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
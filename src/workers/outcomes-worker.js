// Outcomes Worker - Business Outcome CRUD Operations
// Handles creation, reading, updating, and deletion of business outcomes

import { authenticateRequest } from '../utils/auth-utils.js';
import { errorResponse, successResponse, logAuditEvent } from '../utils/db-utils.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;
    
    // CORS handling
    if (method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization'
        }
      });
    }
    
    // Authentication required
    const user = await authenticateRequest(request, env);
    if (!user) {
      return errorResponse('Authentication required', 401);
    }
    
    // Role-based access: CEOs can do everything, Managers can read
    if (user.role === 'employee') {
      return errorResponse('Insufficient permissions', 403);
    }
    
    try {
      // Route to appropriate handler
      if (url.pathname === '/api/outcomes' && method === 'GET') {
        return getOutcomes(request, user, env);
      }
      
      if (url.pathname === '/api/outcomes' && method === 'POST') {
        if (user.role !== 'ceo') {
          return errorResponse('Only CEOs can create outcomes', 403);
        }
        return createOutcome(request, user, env, ctx);
      }
      
      const outcomeIdMatch = url.pathname.match(/^\/api\/outcomes\/([^\/]+)$/);
      if (outcomeIdMatch && method === 'GET') {
        return getOutcome(outcomeIdMatch[1], user, env);
      }
      
      if (outcomeIdMatch && method === 'PUT') {
        if (user.role !== 'ceo') {
          return errorResponse('Only CEOs can update outcomes', 403);
        }
        return updateOutcome(outcomeIdMatch[1], request, user, env, ctx);
      }
      
      if (outcomeIdMatch && method === 'DELETE') {
        if (user.role !== 'ceo') {
          return errorResponse('Only CEOs can delete outcomes', 403);
        }
        return deleteOutcome(outcomeIdMatch[1], user, env, ctx);
      }
      
      const analyzeMatch = url.pathname.match(/^\/api\/outcomes\/([^\/]+)\/analyze$/);
      if (analyzeMatch && method === 'POST') {
        return triggerAnalysis(analyzeMatch[1], request, user, env, ctx);
      }
      
      const activitiesMatch = url.pathname.match(/^\/api\/outcomes\/([^\/]+)\/activities$/);
      if (activitiesMatch && method === 'GET') {
        return getOutcomeActivities(activitiesMatch[1], user, env);
      }
      
      return errorResponse('Endpoint not found', 404);
      
    } catch (error) {
      console.error('Outcomes worker error:', error);
      return errorResponse('Service error: ' + error.message, 500);
    }
  }
};

async function getOutcomes(request, user, env) {
  try {
    const url = new URL(request.url);
    const status = url.searchParams.get('status');
    const priority = url.searchParams.get('priority');
    const limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 100);
    const offset = parseInt(url.searchParams.get('offset')) || 0;
    
    // Build query with filters
    let query = `
      SELECT bo.*, u.name as creator_name
      FROM business_outcomes bo
      LEFT JOIN users u ON bo.created_by = u.id
      WHERE bo.organization_id = ?
    `;
    
    const params = [user.organizationId];
    
    if (status) {
      query += ' AND bo.status = ?';
      params.push(status);
    }
    
    if (priority) {
      query += ' AND bo.priority = ?';
      params.push(priority);
    }
    
    query += ' ORDER BY bo.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);
    
    const outcomes = await env.DB.prepare(query).bind(...params).all();
    
    // Get total count for pagination
    let countQuery = 'SELECT COUNT(*) as total FROM business_outcomes WHERE organization_id = ?';
    const countParams = [user.organizationId];
    
    if (status) {
      countQuery += ' AND status = ?';
      countParams.push(status);
    }
    
    if (priority) {
      countQuery += ' AND priority = ?';
      countParams.push(priority);
    }
    
    const totalCount = await env.DB.prepare(countQuery).bind(...countParams).first();
    
    // Parse AI analysis for each outcome
    const processedOutcomes = outcomes.results.map(outcome => ({
      ...outcome,
      ai_analysis: outcome.ai_analysis ? JSON.parse(outcome.ai_analysis) : null,
      timeline_start: outcome.timeline_start * 1000, // Convert to milliseconds
      timeline_end: outcome.timeline_end * 1000
    }));
    
    return successResponse({
      outcomes: processedOutcomes,
      pagination: {
        total: totalCount.total,
        limit,
        offset,
        has_next: offset + limit < totalCount.total
      }
    });
    
  } catch (error) {
    console.error('Get outcomes error:', error);
    return errorResponse('Failed to retrieve outcomes', 500);
  }
}

async function createOutcome(request, user, env, ctx) {
  try {
    const {
      title,
      description,
      target_value,
      target_metric,
      timeline_start,
      timeline_end,
      priority = 'medium'
    } = await request.json();
    
    // Validation
    const errors = validateOutcomeInput({
      title, description, target_value, target_metric,
      timeline_start, timeline_end, priority
    });
    
    if (errors.length > 0) {
      return errorResponse('Validation errors: ' + errors.join(', '), 400);
    }
    
    const outcomeId = crypto.randomUUID();
    const now = Date.now();
    
    // Convert timeline from milliseconds to seconds for storage
    const startTimestamp = Math.floor(timeline_start / 1000);
    const endTimestamp = Math.floor(timeline_end / 1000);
    
    // Create outcome
    await env.DB.prepare(`
      INSERT INTO business_outcomes (
        id, organization_id, created_by, title, description,
        target_value, target_metric, timeline_start, timeline_end,
        priority, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      outcomeId,
      user.organizationId,
      user.userId,
      title,
      description,
      target_value,
      target_metric,
      startTimestamp,
      endTimestamp,
      priority,
      'draft',
      Math.floor(now / 1000),
      Math.floor(now / 1000)
    ).run();
    
    // Log audit event
    ctx.waitUntil(logAuditEvent({
      userId: user.userId,
      organizationId: user.organizationId,
      action: 'outcome_created',
      resourceType: 'business_outcome',
      resourceId: outcomeId,
      metadata: { title, priority, timeline_months: Math.round((endTimestamp - startTimestamp) / (30 * 24 * 60 * 60)) }
    }, request, env));
    
    // Return created outcome
    const createdOutcome = await env.DB.prepare(
      'SELECT * FROM business_outcomes WHERE id = ?'
    ).bind(outcomeId).first();
    
    return successResponse({
      id: outcomeId,
      ...createdOutcome,
      timeline_start: createdOutcome.timeline_start * 1000,
      timeline_end: createdOutcome.timeline_end * 1000,
      message: 'Outcome created successfully'
    }, 201);
    
  } catch (error) {
    console.error('Create outcome error:', error);
    return errorResponse('Failed to create outcome', 500);
  }
}

async function getOutcome(outcomeId, user, env) {
  try {
    const outcome = await env.DB.prepare(`
      SELECT bo.*, u.name as creator_name
      FROM business_outcomes bo
      LEFT JOIN users u ON bo.created_by = u.id
      WHERE bo.id = ? AND bo.organization_id = ?
    `).bind(outcomeId, user.organizationId).first();
    
    if (!outcome) {
      return errorResponse('Outcome not found', 404);
    }
    
    // Get associated activities
    const activities = await env.DB.prepare(
      'SELECT * FROM outcome_activities WHERE business_outcome_id = ? ORDER BY priority_order ASC'
    ).bind(outcomeId).all();
    
    // Get milestones
    const milestones = await env.DB.prepare(
      'SELECT * FROM outcome_milestones WHERE business_outcome_id = ? ORDER BY target_date ASC'
    ).bind(outcomeId).all();
    
    // Process the outcome data
    const processedOutcome = {
      ...outcome,
      ai_analysis: outcome.ai_analysis ? JSON.parse(outcome.ai_analysis) : null,
      timeline_start: outcome.timeline_start * 1000,
      timeline_end: outcome.timeline_end * 1000,
      activities: activities.results.map(activity => ({
        ...activity,
        skills_required: JSON.parse(activity.skills_required || '[]'),
        dependencies: JSON.parse(activity.dependencies || '[]')
      })),
      milestones: milestones.results.map(milestone => ({
        ...milestone,
        deliverables: JSON.parse(milestone.deliverables || '[]')
      }))
    };
    
    return successResponse(processedOutcome);
    
  } catch (error) {
    console.error('Get outcome error:', error);
    return errorResponse('Failed to retrieve outcome', 500);
  }
}

async function updateOutcome(outcomeId, request, user, env, ctx) {
  try {
    const updateData = await request.json();
    
    // Check if outcome exists and belongs to organization
    const existingOutcome = await env.DB.prepare(
      'SELECT * FROM business_outcomes WHERE id = ? AND organization_id = ?'
    ).bind(outcomeId, user.organizationId).first();
    
    if (!existingOutcome) {
      return errorResponse('Outcome not found', 404);
    }
    
    // Build update query dynamically
    const allowedFields = [
      'title', 'description', 'target_value', 'target_metric',
      'timeline_start', 'timeline_end', 'priority', 'status'
    ];
    
    const updates = [];
    const params = [];
    
    for (const [key, value] of Object.entries(updateData)) {
      if (allowedFields.includes(key) && value !== undefined) {
        updates.push(`${key} = ?`);
        
        // Convert timeline fields to seconds
        if (key === 'timeline_start' || key === 'timeline_end') {
          params.push(Math.floor(value / 1000));
        } else {
          params.push(value);
        }
      }
    }
    
    if (updates.length === 0) {
      return errorResponse('No valid fields to update', 400);
    }
    
    // Add updated_at
    updates.push('updated_at = ?');
    params.push(Math.floor(Date.now() / 1000));
    
    // Add WHERE clause params
    params.push(outcomeId);
    
    // Execute update
    await env.DB.prepare(`
      UPDATE business_outcomes 
      SET ${updates.join(', ')} 
      WHERE id = ?
    `).bind(...params).run();
    
    // Log audit event
    ctx.waitUntil(logAuditEvent({
      userId: user.userId,
      organizationId: user.organizationId,
      action: 'outcome_updated',
      resourceType: 'business_outcome',
      resourceId: outcomeId,
      metadata: { updated_fields: Object.keys(updateData) }
    }, request, env));
    
    return successResponse({ message: 'Outcome updated successfully' });
    
  } catch (error) {
    console.error('Update outcome error:', error);
    return errorResponse('Failed to update outcome', 500);
  }
}

async function deleteOutcome(outcomeId, user, env, ctx) {
  try {
    // Check if outcome exists
    const outcome = await env.DB.prepare(
      'SELECT * FROM business_outcomes WHERE id = ? AND organization_id = ?'
    ).bind(outcomeId, user.organizationId).first();
    
    if (!outcome) {
      return errorResponse('Outcome not found', 404);
    }
    
    // Delete related data first (foreign key constraints)
    await env.DB.prepare('DELETE FROM outcome_risks WHERE business_outcome_id = ?').bind(outcomeId).run();
    await env.DB.prepare('DELETE FROM outcome_milestones WHERE business_outcome_id = ?').bind(outcomeId).run();
    await env.DB.prepare('DELETE FROM outcome_activities WHERE business_outcome_id = ?').bind(outcomeId).run();
    
    // Delete the outcome
    await env.DB.prepare('DELETE FROM business_outcomes WHERE id = ?').bind(outcomeId).run();
    
    // Log audit event
    ctx.waitUntil(logAuditEvent({
      userId: user.userId,
      organizationId: user.organizationId,
      action: 'outcome_deleted',
      resourceType: 'business_outcome',
      resourceId: outcomeId,
      metadata: { title: outcome.title }
    }, request, env));
    
    return successResponse({ message: 'Outcome deleted successfully' });
    
  } catch (error) {
    console.error('Delete outcome error:', error);
    return errorResponse('Failed to delete outcome', 500);
  }
}

async function triggerAnalysis(outcomeId, request, user, env, ctx) {
  try {
    // This endpoint will call the AI planning worker
    const analysisRequest = new Request(`${request.url.origin}/api/ai/analyze-outcome`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': request.headers.get('Authorization')
      },
      body: JSON.stringify({ 
        outcomeId,
        includeRiskAnalysis: true
      })
    });
    
    // Forward to AI planning worker
    const aiWorker = await import('./ai-planning-worker.js');
    const response = await aiWorker.default.fetch(analysisRequest, env, ctx);
    
    // Return the AI worker response
    return response;
    
  } catch (error) {
    console.error('Trigger analysis error:', error);
    return errorResponse('Failed to trigger AI analysis', 500);
  }
}

function validateOutcomeInput(data) {
  const errors = [];
  
  if (!data.title || data.title.length < 10) {
    errors.push('Title must be at least 10 characters');
  }
  
  if (!data.target_value || data.target_value.length < 5) {
    errors.push('Target value must be specific and measurable');
  }
  
  if (!data.timeline_start || !data.timeline_end) {
    errors.push('Both start and end dates are required');
  }
  
  if (data.timeline_end <= data.timeline_start) {
    errors.push('End date must be after start date');
  }
  
  const validPriorities = ['low', 'medium', 'high', 'critical'];
  if (data.priority && !validPriorities.includes(data.priority)) {
    errors.push('Priority must be one of: ' + validPriorities.join(', '));
  }
  
  // Check timeline is reasonable (not more than 3 years)
  const timelineDays = (data.timeline_end - data.timeline_start) / (24 * 60 * 60 * 1000);
  if (timelineDays > 1095) { // 3 years
    errors.push('Timeline should not exceed 3 years');
  }
  
  if (timelineDays < 1) {
    errors.push('Timeline must be at least 1 day');
  }
  
  return errors;
}
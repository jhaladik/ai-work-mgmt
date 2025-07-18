// AI Planning Worker - Claude API Integration for Business Outcome Analysis
// Handles AI-powered backward planning and analysis

import { 
  buildBackwardPlanningPrompt, 
  buildRiskAnalysisPrompt,
  buildActivityBreakdownPrompt,
  buildProgressAnalysisPrompt,
  generateCacheKey,
  validatePromptInputs
} from '../utils/ai-prompts.js';

import { authenticateRequest } from '../utils/auth-utils.js';
import { errorResponse, successResponse, logAuditEvent } from '../utils/db-utils.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // CORS handling
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization'
        }
      });
    }
    
    // Authentication required for all AI endpoints
    const user = await authenticateRequest(request, env);
    if (!user) {
      return errorResponse('Authentication required', 401);
    }
    
    // Role-based access: Only CEOs and Managers can use AI planning
    if (user.role === 'employee') {
      return errorResponse('Insufficient permissions for AI planning', 403);
    }
    
    try {
      switch (url.pathname) {
        case '/api/ai/analyze-outcome':
          return analyzeOutcome(request, env, ctx);
        case '/api/ai/breakdown-activity':
          return breakdownActivity(request, env, ctx);
        case '/api/ai/analyze-progress':
          return analyzeProgress(request, env, ctx);
        case '/api/ai/optimize-team':
          return optimizeTeam(request, env, ctx);
        default:
          return errorResponse('AI endpoint not found', 404);
      }
    } catch (error) {
      console.error('AI Planning Worker error:', error);
      return errorResponse('AI service error: ' + error.message, 500);
    }
  }
};

async function analyzeOutcome(request, env, ctx) {
  try {
    const { outcomeId, includeRiskAnalysis = true } = await request.json();
    const user = request.user;
    
    // Get outcome from database
    const outcome = await env.DB.prepare(
      'SELECT * FROM business_outcomes WHERE id = ? AND organization_id = ?'
    ).bind(outcomeId, user.organizationId).first();
    
    if (!outcome) {
      return errorResponse('Outcome not found', 404);
    }
    
    // Validate outcome data for AI processing
    const validationErrors = validatePromptInputs(outcome);
    if (validationErrors.length > 0) {
      return errorResponse('Invalid outcome data: ' + validationErrors.join(', '), 400);
    }
    
    // Check cache first
    const cacheKey = generateCacheKey('backward_planning', { outcomeId, includeRiskAnalysis });
    const cached = await getCachedAnalysis(cacheKey, env);
    if (cached) {
      return successResponse(cached);
    }
    
    // Get organization context for better AI analysis
    const orgContext = await getOrganizationContext(user.organizationId, env);
    
    // Generate AI analysis
    const analysis = await generateBackwardPlan(outcome, orgContext, env);
    
    // Generate risk analysis if requested
    if (includeRiskAnalysis && analysis.required_activities) {
      analysis.risk_analysis = await generateRiskAnalysis(outcome, analysis.required_activities, env);
    }
    
    // Cache the results for 2 hours
    ctx.waitUntil(cacheAnalysis(cacheKey, analysis, 7200, env));
    
    // Store analysis in database
    ctx.waitUntil(storeAnalysisInDB(outcomeId, analysis, env));
    
    // Log audit event
    ctx.waitUntil(logAuditEvent({
      userId: user.userId,
      organizationId: user.organizationId,
      action: 'ai_analysis_generated',
      resourceType: 'business_outcome',
      resourceId: outcomeId,
      metadata: { analysis_type: 'backward_planning', cache_hit: false }
    }, request, env));
    
    return successResponse(analysis);
    
  } catch (error) {
    console.error('Outcome analysis error:', error);
    return errorResponse('Failed to analyze outcome', 500);
  }
}

async function generateBackwardPlan(outcome, orgContext, env) {
  const prompt = buildBackwardPlanningPrompt(outcome, orgContext);
  
  try {
    const response = await callClaudeAPI(prompt, env);
    const analysis = parseAIResponse(response);
    
    // Validate the AI response structure
    if (!analysis.required_activities || !Array.isArray(analysis.required_activities)) {
      throw new Error('Invalid AI response: missing required activities');
    }
    
    // Add unique IDs to activities
    analysis.required_activities = analysis.required_activities.map((activity, index) => ({
      ...activity,
      id: `activity_${outcomeId}_${index + 1}`,
      created_by_ai: true
    }));
    
    return analysis;
    
  } catch (error) {
    console.error('AI backward planning failed:', error);
    
    // Return fallback analysis
    return getFallbackAnalysis(outcome);
  }
}

async function generateRiskAnalysis(outcome, activities, env) {
  const prompt = buildRiskAnalysisPrompt(outcome, activities);
  
  try {
    const response = await callClaudeAPI(prompt, env);
    return parseAIResponse(response);
  } catch (error) {
    console.error('Risk analysis failed:', error);
    return {
      risks: [{
        category: 'technical',
        description: 'AI risk analysis temporarily unavailable',
        probability: 0.1,
        impact: 'low',
        mitigation_strategy: 'Manual risk assessment recommended'
      }],
      overall_risk_score: 0.3
    };
  }
}

async function breakdownActivity(request, env, ctx) {
  try {
    const { activityId, teamContext } = await request.json();
    const user = request.user;
    
    // Get activity from database
    const activity = await env.DB.prepare(
      `SELECT oa.*, bo.organization_id 
       FROM outcome_activities oa 
       JOIN business_outcomes bo ON oa.business_outcome_id = bo.id 
       WHERE oa.id = ? AND bo.organization_id = ?`
    ).bind(activityId, user.organizationId).first();
    
    if (!activity) {
      return errorResponse('Activity not found', 404);
    }
    
    // Parse skills_required from JSON
    activity.skills_required = JSON.parse(activity.skills_required || '[]');
    
    // Check cache
    const cacheKey = generateCacheKey('activity_breakdown', { activityId, teamContext });
    const cached = await getCachedAnalysis(cacheKey, env);
    if (cached) {
      return successResponse(cached);
    }
    
    // Generate task breakdown
    const prompt = buildActivityBreakdownPrompt(activity, teamContext);
    const response = await callClaudeAPI(prompt, env);
    const breakdown = parseAIResponse(response);
    
    // Cache for 1 hour
    ctx.waitUntil(cacheAnalysis(cacheKey, breakdown, 3600, env));
    
    return successResponse(breakdown);
    
  } catch (error) {
    console.error('Activity breakdown error:', error);
    return errorResponse('Failed to breakdown activity', 500);
  }
}

async function callClaudeAPI(prompt, env) {
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': env.CLAUDE_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.3 // Lower temperature for more consistent business analysis
    })
  });
  
  if (!response.ok) {
    const errorData = await response.text();
    throw new Error(`Claude API error (${response.status}): ${errorData}`);
  }
  
  const data = await response.json();
  return data.content[0].text;
}

function parseAIResponse(responseText) {
  try {
    // Clean up the response (remove any markdown formatting)
    const cleaned = responseText
      .replace(/```json\n?/g, '')
      .replace(/```\n?/g, '')
      .trim();
    
    return JSON.parse(cleaned);
  } catch (error) {
    console.error('Failed to parse AI response:', error);
    console.error('Raw response:', responseText);
    throw new Error('Invalid JSON response from AI');
  }
}

async function getOrganizationContext(organizationId, env) {
  try {
    // Get team information
    const team = await env.DB.prepare(
      'SELECT COUNT(*) as team_size FROM users WHERE organization_id = ? AND is_active = 1'
    ).bind(organizationId).first();
    
    // Get available skills across the organization
    const skillsQuery = await env.DB.prepare(
      'SELECT skills FROM users WHERE organization_id = ? AND is_active = 1 AND skills IS NOT NULL'
    ).bind(organizationId).all();
    
    const allSkills = new Set();
    skillsQuery.results.forEach(user => {
      try {
        const skills = JSON.parse(user.skills || '[]');
        skills.forEach(skill => allSkills.add(skill));
      } catch (e) {
        // Skip invalid JSON
      }
    });
    
    // Get previous outcomes for learning
    const previousOutcomes = await env.DB.prepare(
      'SELECT COUNT(*) as completed_count FROM business_outcomes WHERE organization_id = ? AND status = "completed"'
    ).bind(organizationId).first();
    
    return {
      teamSize: team.team_size,
      availableSkills: Array.from(allSkills),
      previousOutcomes: previousOutcomes.completed_count
    };
  } catch (error) {
    console.error('Error getting organization context:', error);
    return {};
  }
}

async function getCachedAnalysis(cacheKey, env) {
  try {
    const cached = await env.SESSIONS.get(cacheKey);
    return cached ? JSON.parse(cached) : null;
  } catch (error) {
    console.error('Cache retrieval error:', error);
    return null;
  }
}

async function cacheAnalysis(cacheKey, analysis, ttl, env) {
  try {
    await env.SESSIONS.put(cacheKey, JSON.stringify(analysis), { expirationTtl: ttl });
  } catch (error) {
    console.error('Cache storage error:', error);
  }
}

async function storeAnalysisInDB(outcomeId, analysis, env) {
  try {
    await env.DB.prepare(
      'UPDATE business_outcomes SET ai_analysis = ?, success_probability = ?, updated_at = ? WHERE id = ?'
    ).bind(
      JSON.stringify(analysis),
      analysis.success_probability || null,
      Date.now(),
      outcomeId
    ).run();
  } catch (error) {
    console.error('Database storage error:', error);
  }
}

function getFallbackAnalysis(outcome) {
  // Simple fallback when AI is unavailable
  const timelineMonths = Math.ceil((outcome.timeline_end - outcome.timeline_start) / (30 * 24 * 60 * 60));
  
  return {
    required_activities: [{
      id: 'fallback_activity_1',
      title: 'Plan and execute outcome strategy',
      description: 'Develop detailed plan to achieve the specified outcome',
      estimated_hours: timelineMonths * 40,
      skills_required: ['Project Management', 'Strategic Planning'],
      timeline_position: `${timelineMonths} months`,
      success_probability: 0.7,
      dependencies: []
    }],
    resource_requirements: {
      total_hours: timelineMonths * 40,
      recommended_team_size: Math.max(2, Math.min(timelineMonths, 5)),
      specialized_skills: ['Project Management'],
      budget_estimate: 'To be determined'
    },
    success_probability: 0.7,
    risk_factors: [{
      description: 'Limited AI analysis available',
      probability: 1.0,
      impact: 'medium',
      mitigation: 'Manual planning recommended'
    }],
    key_milestones: [{
      title: 'Outcome completion',
      target_date: new Date(outcome.timeline_end * 1000).toISOString().split('T')[0],
      deliverables: ['Achieved target value'],
      success_criteria: outcome.target_value
    }],
    ai_service_available: false
  };
}
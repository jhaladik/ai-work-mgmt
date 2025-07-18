// AI Prompt Templates for Business Outcome Analysis
// Structured prompts for Claude API integration

export function buildBackwardPlanningPrompt(outcome, organizationContext = {}) {
  const contextInfo = organizationContext.teamSize ? 
    `\nORGANIZATION CONTEXT:
    - Team Size: ${organizationContext.teamSize} people
    - Industry: ${organizationContext.industry || 'Not specified'}
    - Previous Outcomes: ${organizationContext.previousOutcomes || 'None specified'}
    - Available Skills: ${organizationContext.availableSkills?.join(', ') || 'Not specified'}` : '';

  return `You are an expert business strategist and project planner. Analyze this business outcome and create a comprehensive backward planning analysis.

BUSINESS OUTCOME DETAILS:
- Title: ${outcome.title}
- Target Value: ${outcome.target_value}
- Target Metric: ${outcome.target_metric || 'Not specified'}
- Timeline: ${new Date(outcome.timeline_start * 1000).toLocaleDateString()} to ${new Date(outcome.timeline_end * 1000).toLocaleDateString()}
- Description: ${outcome.description}
- Priority: ${outcome.priority}${contextInfo}

ANALYSIS REQUIREMENTS:
Create a backward planning strategy working from the desired outcome to current state. Focus on practical, actionable activities that a team can execute.

Provide your response as a JSON object with this exact structure:
{
  "required_activities": [
    {
      "title": "Activity name (specific and actionable)",
      "description": "Detailed description of what needs to be done",
      "estimated_hours": 40,
      "skills_required": ["skill1", "skill2"],
      "timeline_position": "Q1 2025" or "Month 1-2",
      "success_probability": 0.85,
      "dependencies": ["activity_id_1", "activity_id_2"]
    }
  ],
  "resource_requirements": {
    "total_hours": 200,
    "recommended_team_size": 5,
    "specialized_skills": ["AI Development", "Marketing"],
    "budget_estimate": "€50,000-€75,000",
    "key_roles_needed": ["Project Manager", "Developer"]
  },
  "success_probability": 0.75,
  "risk_factors": [
    {
      "description": "Market volatility may affect demand",
      "probability": 0.3,
      "impact": "high",
      "mitigation": "Diversify target markets"
    }
  ],
  "key_milestones": [
    {
      "title": "Milestone name",
      "target_date": "2025-10-15",
      "deliverables": ["deliverable1", "deliverable2"],
      "success_criteria": "Specific measurable criteria"
    }
  ],
  "critical_path": ["activity_1", "activity_2", "activity_3"],
  "assumptions": [
    "Market conditions remain stable",
    "Team remains fully staffed"
  ]
}

IMPORTANT: Respond with ONLY valid JSON, no additional text or formatting.`;
}

export function buildRiskAnalysisPrompt(outcome, activities) {
  return `Analyze potential risks for this business outcome and its planned activities.

OUTCOME: ${outcome.title}
TARGET: ${outcome.target_value}
TIMELINE: ${Math.round((outcome.timeline_end - outcome.timeline_start) / (30 * 24 * 60 * 60))} months

PLANNED ACTIVITIES:
${activities.map(a => `- ${a.title}: ${a.estimated_hours}h, Skills: ${a.skills_required.join(', ')}`).join('\n')}

Identify and assess risks. Respond with JSON:
{
  "risks": [
    {
      "category": "technical|market|resource|timeline",
      "description": "Specific risk description",
      "probability": 0.3,
      "impact": "low|medium|high|critical",
      "affected_activities": ["activity1"],
      "mitigation_strategy": "Specific mitigation approach",
      "contingency_plan": "What to do if risk occurs"
    }
  ],
  "overall_risk_score": 0.4,
  "recommended_buffers": {
    "time_buffer": "20%",
    "resource_buffer": "15%",
    "budget_buffer": "25%"
  }
}

Respond with ONLY valid JSON.`;
}

export function buildActivityBreakdownPrompt(activity, teamContext) {
  return `Break down this high-level activity into specific, executable tasks.

ACTIVITY: ${activity.title}
DESCRIPTION: ${activity.description}
ESTIMATED HOURS: ${activity.estimated_hours}
REQUIRED SKILLS: ${activity.skills_required.join(', ')}
TIMELINE: ${activity.timeline_position}

TEAM CONTEXT:
${teamContext.availableRoles?.map(role => `- ${role.name}: ${role.skills.join(', ')}`).join('\n') || 'No team context provided'}

Create specific tasks that can be assigned to team members. Respond with JSON:
{
  "tasks": [
    {
      "title": "Specific task name",
      "description": "Detailed task description",
      "estimated_hours": 8,
      "skills_required": ["specific_skill"],
      "deliverables": ["deliverable1"],
      "acceptance_criteria": ["criteria1", "criteria2"],
      "priority": "high|medium|low",
      "dependencies": ["task_id"]
    }
  ],
  "task_sequence": ["task1", "task2", "task3"],
  "quality_gates": [
    {
      "checkpoint": "After task completion",
      "criteria": "Specific quality criteria",
      "reviewer_role": "Manager"
    }
  ]
}

Respond with ONLY valid JSON.`;
}

export function buildProgressAnalysisPrompt(outcome, currentProgress, actualData) {
  return `Analyze the progress of this business outcome and provide insights for optimization.

ORIGINAL OUTCOME:
- Title: ${outcome.title}
- Target: ${outcome.target_value}
- Timeline: ${new Date(outcome.timeline_start * 1000).toLocaleDateString()} to ${new Date(outcome.timeline_end * 1000).toLocaleDateString()}
- Original Success Probability: ${outcome.success_probability || 'Not set'}

CURRENT PROGRESS:
- Completion Percentage: ${currentProgress.completion_percentage}%
- Activities Completed: ${currentProgress.completed_activities}/${currentProgress.total_activities}
- Hours Spent: ${currentProgress.hours_spent}/${currentProgress.estimated_hours}
- Days Remaining: ${currentProgress.days_remaining}

ACTUAL DATA:
${Object.entries(actualData).map(([key, value]) => `- ${key}: ${value}`).join('\n')}

Provide analysis and recommendations. Respond with JSON:
{
  "current_status": "on_track|at_risk|behind_schedule|ahead_of_schedule",
  "updated_success_probability": 0.82,
  "performance_insights": [
    {
      "metric": "Time utilization",
      "actual": "120%",
      "expected": "100%",
      "variance_reason": "Underestimated complexity"
    }
  ],
  "recommendations": [
    {
      "type": "resource_adjustment|timeline_change|scope_modification",
      "description": "Specific recommendation",
      "urgency": "immediate|within_week|next_milestone",
      "expected_impact": "Positive impact description"
    }
  ],
  "forecast": {
    "projected_completion_date": "2025-12-15",
    "confidence_level": 0.85,
    "final_success_probability": 0.78
  },
  "lessons_learned": [
    "Specific lesson for future planning"
  ]
}

Respond with ONLY valid JSON.`;
}

export function buildTeamOptimizationPrompt(outcome, team, currentAssignments) {
  return `Optimize team assignments for this business outcome based on skills and capacity.

OUTCOME: ${outcome.title}
ACTIVITIES: ${outcome.required_activities?.length || 0} planned activities

TEAM MEMBERS:
${team.map(member => `
- ${member.name} (${member.role})
  Skills: ${member.skills.join(', ')}
  Capacity: ${member.capacity_hours_per_week}h/week
  Current Load: ${member.current_hours || 0}h/week
`).join('')}

CURRENT ASSIGNMENTS:
${currentAssignments.map(a => `- ${a.activity_title}: ${a.assignee_name} (${a.estimated_hours}h)`).join('\n')}

Provide optimization recommendations. Respond with JSON:
{
  "optimized_assignments": [
    {
      "activity_id": "activity_1",
      "recommended_assignee": "member_name",
      "reasoning": "Why this assignment is optimal",
      "success_probability": 0.9,
      "skill_match_score": 0.85,
      "capacity_utilization": 0.7
    }
  ],
  "team_balance": {
    "utilization_variance": 0.15,
    "skill_coverage": 0.9,
    "risk_concentration": "low|medium|high"
  },
  "recommendations": [
    {
      "type": "hiring|training|rebalancing",
      "description": "Specific recommendation",
      "priority": "high|medium|low"
    }
  ]
}

Respond with ONLY valid JSON.`;
}

// Utility function to generate cache keys
export function generateCacheKey(type, inputData) {
  const dataString = JSON.stringify(inputData);
  return `${type}:${hashString(dataString)}`;
}

// Simple hash function for cache keys
function hashString(str) {
  let hash = 0;
  if (str.length === 0) return hash;
  
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  
  return Math.abs(hash).toString(36);
}

// Prompt validation
export function validatePromptInputs(outcome) {
  const errors = [];
  
  if (!outcome.title || outcome.title.length < 10) {
    errors.push('Outcome title must be at least 10 characters');
  }
  
  if (!outcome.target_value || outcome.target_value.length < 5) {
    errors.push('Target value must be specific and measurable');
  }
  
  if (!outcome.timeline_start || !outcome.timeline_end) {
    errors.push('Timeline start and end dates are required');
  }
  
  if (outcome.timeline_end <= outcome.timeline_start) {
    errors.push('End date must be after start date');
  }
  
  const timelineMonths = (outcome.timeline_end - outcome.timeline_start) / (30 * 24 * 60 * 60);
  if (timelineMonths > 36) {
    errors.push('Timeline should not exceed 36 months for effective AI planning');
  }
  
  return errors;
}
// Outcome Form Component - Reusable Business Outcome Creation/Editing
// Handles form validation, submission, and AI integration

class OutcomeFormComponent {
  constructor(options = {}) {
    this.apiBase = options.apiBase || 'https://ai-work-mgmt.jhaladik.workers.dev/api';
    this.onSuccess = options.onSuccess || (() => {});
    this.onError = options.onError || ((error) => console.error(error));
    this.mode = options.mode || 'create'; // 'create' or 'edit'
    this.outcomeId = options.outcomeId || null;
    this.outcome = options.outcome || null;
    
    this.validationRules = {
      title: { min: 10, max: 200, required: true },
      target_value: { min: 5, max: 500, required: true },
      timeline_start: { required: true },
      timeline_end: { required: true },
      priority: { options: ['low', 'medium', 'high', 'critical'], required: true }
    };
  }

  render(containerId) {
    const container = document.getElementById(containerId);
    if (!container) {
      throw new Error(`Container with id "${containerId}" not found`);
    }

    const formHTML = this.generateFormHTML();
    container.innerHTML = formHTML;
    
    this.bindEvents();
    this.populateForm();
    this.initializeValidation();
  }

  generateFormHTML() {
    const submitText = this.mode === 'create' ? 'Create Outcome' : 'Update Outcome';
    const titleText = this.mode === 'create' ? 'Create Business Outcome' : 'Edit Business Outcome';

    return `
      <div class="bg-white rounded-lg shadow-lg">
        <div class="px-6 py-4 border-b border-gray-200">
          <h3 class="text-lg font-medium text-gray-900">${titleText}</h3>
          <p class="text-sm text-gray-600 mt-1">Define your strategic business outcome with measurable targets and timeline</p>
        </div>

        <form id="outcomeForm" class="px-6 py-4">
          <!-- Title -->
          <div class="mb-6">
            <label for="title" class="block text-sm font-medium text-gray-700 mb-1">
              Outcome Title *
            </label>
            <input 
              type="text" 
              id="title" 
              name="title" 
              required
              maxlength="200"
              class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              placeholder="e.g., Increase Q4 revenue by 25%"
            >
            <div id="titleError" class="text-red-600 text-sm mt-1 hidden"></div>
            <div class="text-gray-500 text-xs mt-1">
              <span id="titleCount">0</span>/200 characters (minimum 10)
            </div>
          </div>

          <!-- Description -->
          <div class="mb-6">
            <label for="description" class="block text-sm font-medium text-gray-700 mb-1">
              Description
            </label>
            <textarea 
              id="description" 
              name="description" 
              rows="3"
              maxlength="1000"
              class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              placeholder="Detailed description of the outcome, its strategic importance, and expected impact"
            ></textarea>
            <div class="text-gray-500 text-xs mt-1">
              <span id="descCount">0</span>/1000 characters
            </div>
          </div>

          <!-- Target Value and Metric -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div>
              <label for="targetValue" class="block text-sm font-medium text-gray-700 mb-1">
                Target Value *
              </label>
              <input 
                type="text" 
                id="targetValue" 
                name="target_value" 
                required
                maxlength="500"
                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder="e.g., €2.1M additional revenue"
              >
              <div id="targetValueError" class="text-red-600 text-sm mt-1 hidden"></div>
            </div>
            <div>
              <label for="targetMetric" class="block text-sm font-medium text-gray-700 mb-1">
                Success Metric
              </label>
              <input 
                type="text" 
                id="targetMetric" 
                name="target_metric"
                maxlength="200"
                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder="e.g., Monthly recurring revenue"
              >
            </div>
          </div>

          <!-- Timeline -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div>
              <label for="startDate" class="block text-sm font-medium text-gray-700 mb-1">
                Start Date *
              </label>
              <input 
                type="date" 
                id="startDate" 
                name="timeline_start" 
                required
                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              >
              <div id="startDateError" class="text-red-600 text-sm mt-1 hidden"></div>
            </div>
            <div>
              <label for="endDate" class="block text-sm font-medium text-gray-700 mb-1">
                Target Completion Date *
              </label>
              <input 
                type="date" 
                id="endDate" 
                name="timeline_end" 
                required
                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              >
              <div id="endDateError" class="text-red-600 text-sm mt-1 hidden"></div>
            </div>
          </div>

          <!-- Timeline Information -->
          <div id="timelineInfo" class="mb-6 p-3 bg-blue-50 rounded-md hidden">
            <div class="flex">
              <svg class="w-5 h-5 text-blue-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/>
              </svg>
              <div class="text-sm text-blue-700">
                <p id="timelineDuration"></p>
                <p id="timelineComplexity"></p>
              </div>
            </div>
          </div>

          <!-- Priority -->
          <div class="mb-6">
            <label for="priority" class="block text-sm font-medium text-gray-700 mb-1">
              Priority *
            </label>
            <select 
              id="priority" 
              name="priority" 
              required
              class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
            >
              <option value="medium">Medium - Standard business priority</option>
              <option value="low">Low - Nice to have, flexible timeline</option>
              <option value="high">High - Important for business success</option>
              <option value="critical">Critical - Essential for business survival</option>
            </select>
          </div>

          <!-- AI Preview -->
          <div id="aiPreview" class="mb-6 p-4 bg-purple-50 rounded-md border border-purple-200 hidden">
            <h4 class="text-sm font-medium text-purple-800 mb-2">AI Planning Preview</h4>
            <div class="space-y-2 text-sm text-purple-700">
              <div id="aiEstimatedHours"></div>
              <div id="aiTeamSize"></div>
              <div id="aiComplexity"></div>
            </div>
            <button type="button" id="runPreviewAnalysis" class="mt-2 text-xs bg-purple-600 text-white px-3 py-1 rounded hover:bg-purple-700">
              Run AI Preview
            </button>
          </div>

          <!-- Form Actions -->
          <div class="flex justify-end space-x-3 pt-6 border-t border-gray-200">
            <button 
              type="button" 
              id="cancelBtn" 
              class="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-gray-500"
            >
              Cancel
            </button>
            <button 
              type="submit" 
              id="submitBtn"
              class="px-6 py-2 bg-primary text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <span id="submitSpinner" class="hidden">
                <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              </span>
              <span id="submitText">${submitText}</span>
            </button>
          </div>
        </form>
      </div>
    `;
  }

  bindEvents() {
    const form = document.getElementById('outcomeForm');
    const cancelBtn = document.getElementById('cancelBtn');
    const titleInput = document.getElementById('title');
    const descInput = document.getElementById('description');
    const startDate = document.getElementById('startDate');
    const endDate = document.getElementById('endDate');
    const previewBtn = document.getElementById('runPreviewAnalysis');

    // Form submission
    form.addEventListener('submit', (e) => this.handleSubmit(e));
    
    // Cancel button
    cancelBtn.addEventListener('click', () => this.handleCancel());

    // Character counting
    titleInput.addEventListener('input', () => this.updateCharCount('title', 'titleCount'));
    descInput.addEventListener('input', () => this.updateCharCount('description', 'descCount'));

    // Timeline calculation
    startDate.addEventListener('change', () => this.updateTimelineInfo());
    endDate.addEventListener('change', () => this.updateTimelineInfo());

    // Real-time validation
    titleInput.addEventListener('blur', () => this.validateField('title'));
    document.getElementById('targetValue').addEventListener('blur', () => this.validateField('target_value'));

    // AI preview
    previewBtn.addEventListener('click', () => this.runAIPreview());
  }

  populateForm() {
    if (this.mode === 'edit' && this.outcome) {
      document.getElementById('title').value = this.outcome.title || '';
      document.getElementById('description').value = this.outcome.description || '';
      document.getElementById('targetValue').value = this.outcome.target_value || '';
      document.getElementById('targetMetric').value = this.outcome.target_metric || '';
      document.getElementById('priority').value = this.outcome.priority || 'medium';
      
      if (this.outcome.timeline_start) {
        document.getElementById('startDate').value = new Date(this.outcome.timeline_start).toISOString().split('T')[0];
      }
      
      if (this.outcome.timeline_end) {
        document.getElementById('endDate').value = new Date(this.outcome.timeline_end).toISOString().split('T')[0];
      }

      this.updateCharCount('title', 'titleCount');
      this.updateCharCount('description', 'descCount');
      this.updateTimelineInfo();
    } else {
      this.setDefaultDates();
    }
  }

  setDefaultDates() {
    const now = new Date();
    const startDate = new Date(now.getFullYear(), now.getMonth(), 1);
    const endDate = new Date(now.getFullYear() + 1, now.getMonth(), 0);
    
    document.getElementById('startDate').value = startDate.toISOString().split('T')[0];
    document.getElementById('endDate').value = endDate.toISOString().split('T')[0];
    
    this.updateTimelineInfo();
  }

  initializeValidation() {
    // Show AI preview section
    document.getElementById('aiPreview').classList.remove('hidden');
  }

  updateCharCount(fieldId, countId) {
    const field = document.getElementById(fieldId);
    const counter = document.getElementById(countId);
    
    if (field && counter) {
      counter.textContent = field.value.length;
      
      // Update styling based on limits
      const rule = this.validationRules[fieldId];
      if (rule && rule.max) {
        if (field.value.length > rule.max * 0.9) {
          counter.className = 'text-yellow-600';
        } else if (field.value.length > rule.max * 0.95) {
          counter.className = 'text-red-600';
        } else {
          counter.className = 'text-gray-500';
        }
      }
    }
  }

  updateTimelineInfo() {
    const startDate = document.getElementById('startDate').value;
    const endDate = document.getElementById('endDate').value;
    
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      const diffTime = end - start;
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      const diffMonths = Math.round(diffDays / 30.44);
      
      const timelineInfo = document.getElementById('timelineInfo');
      const durationElement = document.getElementById('timelineDuration');
      const complexityElement = document.getElementById('timelineComplexity');
      
      if (diffDays > 0) {
        timelineInfo.classList.remove('hidden');
        durationElement.textContent = `Duration: ${diffDays} days (${diffMonths} months)`;
        
        let complexity = '';
        if (diffMonths <= 3) {
          complexity = 'Short-term outcome - High focus, limited complexity';
        } else if (diffMonths <= 12) {
          complexity = 'Medium-term outcome - Moderate complexity, multiple milestones';
        } else {
          complexity = 'Long-term outcome - High complexity, strategic planning required';
        }
        
        complexityElement.textContent = complexity;
      } else {
        timelineInfo.classList.add('hidden');
      }
    }
  }

  validateField(fieldName) {
    const field = document.getElementById(fieldName === 'target_value' ? 'targetValue' : fieldName);
    const errorElement = document.getElementById(fieldName + 'Error');
    const rule = this.validationRules[fieldName];
    
    if (!rule) return true;
    
    let isValid = true;
    let errorMessage = '';
    
    // Required validation
    if (rule.required && !field.value.trim()) {
      isValid = false;
      errorMessage = 'This field is required';
    }
    
    // Length validation
    if (isValid && rule.min && field.value.length < rule.min) {
      isValid = false;
      errorMessage = `Minimum ${rule.min} characters required`;
    }
    
    if (isValid && rule.max && field.value.length > rule.max) {
      isValid = false;
      errorMessage = `Maximum ${rule.max} characters allowed`;
    }
    
    // Options validation
    if (isValid && rule.options && !rule.options.includes(field.value)) {
      isValid = false;
      errorMessage = `Must be one of: ${rule.options.join(', ')}`;
    }
    
    // Date validation
    if (fieldName === 'timeline_end') {
      const startDate = new Date(document.getElementById('startDate').value);
      const endDate = new Date(field.value);
      
      if (endDate <= startDate) {
        isValid = false;
        errorMessage = 'End date must be after start date';
      }
    }
    
    // Update UI
    if (isValid) {
      errorElement.classList.add('hidden');
      field.classList.remove('border-red-300');
      field.classList.add('border-gray-300');
    } else {
      errorElement.textContent = errorMessage;
      errorElement.classList.remove('hidden');
      field.classList.add('border-red-300');
      field.classList.remove('border-gray-300');
    }
    
    return isValid;
  }

  async runAIPreview() {
    const previewBtn = document.getElementById('runPreviewAnalysis');
    const originalText = previewBtn.textContent;
    
    try {
      previewBtn.textContent = 'Analyzing...';
      previewBtn.disabled = true;
      
      // Collect current form data
      const formData = this.getFormData();
      
      // Simple client-side estimation (in real app, this would call AI API)
      const timelineMonths = Math.round((formData.timeline_end - formData.timeline_start) / (30.44 * 24 * 60 * 60 * 1000));
      const estimatedHours = Math.max(40, timelineMonths * 60);
      const teamSize = Math.max(2, Math.min(Math.ceil(estimatedHours / 160), 8));
      
      document.getElementById('aiEstimatedHours').textContent = `Estimated effort: ${estimatedHours} hours`;
      document.getElementById('aiTeamSize').textContent = `Recommended team size: ${teamSize} people`;
      
      let complexity = 'Low';
      if (timelineMonths > 6 && estimatedHours > 200) complexity = 'Medium';
      if (timelineMonths > 12 && estimatedHours > 500) complexity = 'High';
      
      document.getElementById('aiComplexity').textContent = `Complexity level: ${complexity}`;
      
    } catch (error) {
      console.error('AI preview error:', error);
      document.getElementById('aiEstimatedHours').textContent = 'Preview unavailable';
    } finally {
      previewBtn.textContent = originalText;
      previewBtn.disabled = false;
    }
  }

  getFormData() {
    const form = document.getElementById('outcomeForm');
    const formData = new FormData(form);
    
    return {
      title: formData.get('title'),
      description: formData.get('description'),
      target_value: formData.get('target_value'),
      target_metric: formData.get('target_metric'),
      timeline_start: new Date(formData.get('timeline_start')).getTime(),
      timeline_end: new Date(formData.get('timeline_end')).getTime(),
      priority: formData.get('priority')
    };
  }

  async handleSubmit(e) {
    e.preventDefault();
    
    // Validate all fields
    const isValid = this.validateForm();
    if (!isValid) {
      this.onError('Please fix validation errors before submitting');
      return;
    }
    
    const data = this.getFormData();
    
    try {
      this.setLoading(true);
      
      const endpoint = this.mode === 'create' ? '/outcomes' : `/outcomes/${this.outcomeId}`;
      const method = this.mode === 'create' ? 'POST' : 'PUT';
      
      const response = await this.makeAuthenticatedRequest(endpoint, {
        method,
        body: JSON.stringify(data)
      });
      
      const result = await response.json();
      
      if (response.ok) {
        this.onSuccess(result, this.mode);
      } else {
        throw new Error(result.error || 'Operation failed');
      }
      
    } catch (error) {
      console.error('Form submission error:', error);
      this.onError(error.message);
    } finally {
      this.setLoading(false);
    }
  }

  validateForm() {
    let isValid = true;
    
    // Validate all fields with rules
    for (const fieldName of Object.keys(this.validationRules)) {
      if (!this.validateField(fieldName)) {
        isValid = false;
      }
    }
    
    return isValid;
  }

  handleCancel() {
    const form = document.getElementById('outcomeForm');
    form.reset();
    
    if (this.mode === 'create') {
      this.setDefaultDates();
    } else {
      this.populateForm();
    }
    
    // Trigger any parent cancel handler
    if (this.onCancel) {
      this.onCancel();
    }
  }

  setLoading(loading) {
    const spinner = document.getElementById('submitSpinner');
    const text = document.getElementById('submitText');
    const button = document.getElementById('submitBtn');
    
    if (loading) {
      spinner.classList.remove('hidden');
      text.textContent = this.mode === 'create' ? 'Creating...' : 'Updating...';
      button.disabled = true;
    } else {
      spinner.classList.add('hidden');
      text.textContent = this.mode === 'create' ? 'Create Outcome' : 'Update Outcome';
      button.disabled = false;
    }
  }

  async makeAuthenticatedRequest(endpoint, options = {}) {
    const token = localStorage.getItem('authToken');
    
    return fetch(`${this.apiBase}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...options.headers
      }
    });
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = OutcomeFormComponent;
}
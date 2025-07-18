// AI Work Management System - Frontend Application
// Main application logic and API communication

class AIWorkManagementApp {
    constructor() {
        this.apiBase = '/api'; // Change this to your actual API endpoint
        this.user = null;
        this.authToken = null;
        
        this.init();
    }
    
    async init() {
        // Check authentication
        this.authToken = localStorage.getItem('authToken');
        const userData = localStorage.getItem('user');
        
        if (!this.authToken || !userData) {
            this.redirectToLogin();
            return;
        }
        
        try {
            this.user = JSON.parse(userData);
            await this.verifyAuth();
            this.setupUI();
            this.loadDashboardData();
        } catch (error) {
            console.error('Initialization error:', error);
            this.redirectToLogin();
        }
    }
    
    async verifyAuth() {
        try {
            const response = await this.makeAuthenticatedRequest('/auth/verify');
            if (!response.ok) {
                throw new Error('Authentication verification failed');
            }
            
            const data = await response.json();
            this.user = data.user;
            localStorage.setItem('user', JSON.stringify(this.user));
        } catch (error) {
            console.error('Auth verification error:', error);
            throw error;
        }
    }
    
    setupUI() {
        // Setup user welcome message
        const userWelcome = document.getElementById('userWelcome');
        if (userWelcome) {
            userWelcome.textContent = `Welcome, ${this.user.name}`;
        }
        
        // Show/hide navigation based on role
        if (this.user.role === 'ceo' || this.user.role === 'manager') {
            const managementNav = document.getElementById('managementNav');
            if (managementNav) {
                managementNav.classList.remove('hidden');
            }
        }
        
        // Setup navigation handlers
        this.setupNavigation();
        
        // Setup click outside handler for user menu
        document.addEventListener('click', (e) => {
            if (!e.target.closest('#userMenu') && !e.target.closest('button')) {
                document.getElementById('userMenu').classList.add('hidden');
            }
        });
    }
    
    setupNavigation() {
        // Handle navigation clicks
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                
                // Update active state
                navItems.forEach(nav => {
                    nav.classList.remove('bg-primary', 'text-white');
                    nav.classList.add('text-gray-700', 'hover:bg-gray-50');
                });
                
                item.classList.add('bg-primary', 'text-white');
                item.classList.remove('text-gray-700', 'hover:bg-gray-50');
            });
        });
    }
    
    async loadDashboardData() {
        try {
            // Load dashboard stats
            await Promise.all([
                this.loadTaskStats(),
                this.loadRecentActivity()
            ]);
        } catch (error) {
            console.error('Error loading dashboard data:', error);
        }
    }
    
    async loadTaskStats() {
        try {
            // For now, use mock data - in real implementation, this would come from API
            const stats = {
                activeTasks: 5,
                hoursWeek: 32,
                completionRate: '85%',
                aiScore: '92/100'
            };
            
            document.getElementById('activeTasks').textContent = stats.activeTasks;
            document.getElementById('hoursWeek').textContent = stats.hoursWeek;
            document.getElementById('completionRate').textContent = stats.completionRate;
            document.getElementById('aiScore').textContent = stats.aiScore;
        } catch (error) {
            console.error('Error loading task stats:', error);
            // Show error state
            document.getElementById('activeTasks').textContent = 'Error';
            document.getElementById('hoursWeek').textContent = 'Error';
            document.getElementById('completionRate').textContent = 'Error';
            document.getElementById('aiScore').textContent = 'Error';
        }
    }
    
    async loadRecentActivity() {
        try {
            const activityContainer = document.getElementById('recentActivity');
            if (!activityContainer) return;
            
            // Mock recent activity data
            const activities = [
                {
                    type: 'task_completed',
                    message: 'Completed "Design system review"',
                    time: '2 hours ago',
                    icon: 'check'
                },
                {
                    type: 'task_assigned',
                    message: 'New task assigned: "API documentation"',
                    time: '4 hours ago',
                    icon: 'plus'
                },
                {
                    type: 'calendar_synced',
                    message: 'Calendar synchronized with Google Calendar',
                    time: '1 day ago',
                    icon: 'calendar'
                }
            ];
            
            activityContainer.innerHTML = activities.map(activity => `
                <div class="flex items-center text-sm">
                    <div class="flex-shrink-0 w-8 h-8 bg-green-100 rounded-full flex items-center justify-center mr-3">
                        ${this.getActivityIcon(activity.icon)}
                    </div>
                    <div class="flex-1">
                        <p class="text-gray-900">${activity.message}</p>
                        <p class="text-gray-500 text-xs">${activity.time}</p>
                    </div>
                </div>
            `).join('');
        } catch (error) {
            console.error('Error loading recent activity:', error);
            document.getElementById('recentActivity').innerHTML = `
                <div class="text-sm text-red-600">Error loading recent activity</div>
            `;
        }
    }
    
    getActivityIcon(type) {
        const icons = {
            check: '<svg class="w-4 h-4 text-green-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>',
            plus: '<svg class="w-4 h-4 text-blue-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/></svg>',
            calendar: '<svg class="w-4 h-4 text-purple-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clip-rule="evenodd"/></svg>'
        };
        return icons[type] || icons.check;
    }
    
    async makeAuthenticatedRequest(endpoint, options = {}) {
        const url = `${this.apiBase}${endpoint}`;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.authToken}`
            }
        };
        
        const mergedOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };
        
        const response = await fetch(url, mergedOptions);
        
        // Handle auth errors
        if (response.status === 401) {
            this.redirectToLogin();
            throw new Error('Authentication required');
        }
        
        return response;
    }
    
    redirectToLogin() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        window.location.href = '/login.html';
    }
}

// Global functions for HTML event handlers
function showSection(sectionName) {
    // Hide all sections
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => section.classList.add('hidden'));
    
    // Show selected section
    const targetSection = document.getElementById(`${sectionName}Section`);
    if (targetSection) {
        targetSection.classList.remove('hidden');
    }
}

function toggleUserMenu() {
    const userMenu = document.getElementById('userMenu');
    if (userMenu) {
        userMenu.classList.toggle('hidden');
    }
}

function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
    window.location.href = '/login.html';
}

// Notification system
class NotificationManager {
    constructor() {
        this.container = this.createContainer();
    }
    
    createContainer() {
        const container = document.createElement('div');
        container.id = 'notifications';
        container.className = 'fixed top-4 right-4 z-50 space-y-2';
        document.body.appendChild(container);
        return container;
    }
    
    show(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `
            max-w-sm w-full bg-white shadow-lg rounded-lg pointer-events-auto
            ${type === 'error' ? 'border-l-4 border-red-400' : 
              type === 'success' ? 'border-l-4 border-green-400' : 
              type === 'warning' ? 'border-l-4 border-yellow-400' : 
              'border-l-4 border-blue-400'}
        `;
        
        notification.innerHTML = `
            <div class="p-4">
                <div class="flex items-start">
                    <div class="ml-3 w-0 flex-1">
                        <p class="text-sm font-medium text-gray-900">${message}</p>
                    </div>
                    <div class="ml-4 flex-shrink-0 flex">
                        <button onclick="this.parentElement.parentElement.parentElement.remove()" 
                                class="bg-white rounded-md inline-flex text-gray-400 hover:text-gray-500">
                            <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        this.container.appendChild(notification);
        
        // Auto-remove after duration
        if (duration > 0) {
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, duration);
        }
        
        return notification;
    }
    
    error(message) {
        return this.show(message, 'error');
    }
    
    success(message) {
        return this.show(message, 'success');
    }
    
    warning(message) {
        return this.show(message, 'warning');
    }
    
    info(message) {
        return this.show(message, 'info');
    }
}

// Loading overlay
class LoadingManager {
    show(message = 'Loading...') {
        // Remove existing overlay
        this.hide();
        
        const overlay = document.createElement('div');
        overlay.id = 'loadingOverlay';
        overlay.className = 'fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50';
        overlay.innerHTML = `
            <div class="bg-white rounded-lg p-6 flex items-center space-x-3">
                <svg class="animate-spin h-5 w-5 text-primary" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span class="text-gray-900">${message}</span>
            </div>
        `;
        
        document.body.appendChild(overlay);
    }
    
    hide() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.remove();
        }
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize global managers
    window.notifications = new NotificationManager();
    window.loading = new LoadingManager();
    
    // Initialize main app
    window.app = new AIWorkManagementApp();
});

// Handle auth errors globally
window.addEventListener('unhandledrejection', (event) => {
    if (event.reason && event.reason.message === 'Authentication required') {
        event.preventDefault(); // Prevent console error
    }
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AIWorkManagementApp, NotificationManager, LoadingManager };
}
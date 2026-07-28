// ============================================
// SECURE WEBSITE — Auth Guard Module v2.0
// Authentication, Authorization & Session Management
// ============================================

class AuthGuard {
    constructor() {
        this.user = null;
        this.session = null;
        this.tokenKey = 'secure_auth_token';
        this.userKey = 'secure_user_data';
        this.sessionKey = 'secure_session';
        this.rememberKey = 'secure_remember';
        this.sessionTimeout = 3600000; // 1 hour
        this.refreshThreshold = 300000; // 5 minutes before expiry
        this.maxSessions = 5;
        this.initialized = false;
        
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    init() {
        this.restoreSession();
        this.setupAutoRefresh();
        this.setupActivityTracking();
        this.initialized = true;
        console.log('🔐 Auth Guard Module Loaded');
    }

    // ============================================
    // LOGIN
    // ============================================
    async login(credentials, rememberMe = false) {
        // Validate credentials
        if (!credentials || (!credentials.email && !credentials.token)) {
            return { success: false, error: 'Invalid credentials.' };
        }

        // Create session
        const session = {
            id: this.generateSessionId(),
            userId: credentials.email || credentials.id || 'user_' + Date.now(),
            email: credentials.email || '',
            name: credentials.name || '',
            role: credentials.role || 'user',
            permissions: credentials.permissions || [],
            createdAt: Date.now(),
            expiresAt: Date.now() + this.sessionTimeout,
            lastActivity: Date.now(),
            rememberMe: rememberMe,
            userAgent: navigator.userAgent.substring(0, 200),
            ip: 'secured'
        };

        // Store session
        this.session = session;
        this.user = {
            id: session.userId,
            email: session.email,
            name: session.name,
            role: session.role,
            permissions: session.permissions
        };

        // Save to storage
        this.saveSession(session, rememberMe);
        this.saveUser(this.user);

        // Log audit
        if (window.Logger) {
            Logger.log('login_success', this.user.email, { role: this.user.role });
        }

        console.log(`✅ User logged in: ${this.user.email} (${this.user.role})`);
        return { success: true, user: this.user, session: session };
    }

    // ============================================
    // LOGOUT
    // ============================================
    logout() {
        // Log audit
        if (window.Logger && this.user) {
            Logger.log('logout', this.user.email);
        }

        // Clear session
        this.user = null;
        this.session = null;

        // Clear storage
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.userKey);
        localStorage.removeItem(this.sessionKey);
        sessionStorage.removeItem(this.sessionKey);
        localStorage.removeItem(this.rememberKey);

        console.log('👋 User logged out');

        // Redirect to login if on protected page
        const protectedPages = ['dashboard.html', 'admin.html'];
        const currentPage = window.location.pathname.split('/').pop();
        if (protectedPages.includes(currentPage)) {
            window.location.href = '/login.html';
        }
    }

    // ============================================
    // SESSION MANAGEMENT
    // ============================================
    saveSession(session, rememberMe = false) {
        const sessionData = JSON.stringify(session);
        
        // Always save to session storage (cleared on browser close)
        sessionStorage.setItem(this.sessionKey, sessionData);
        
        // Save to local storage if remember me
        if (rememberMe) {
            localStorage.setItem(this.sessionKey, sessionData);
            localStorage.setItem(this.rememberKey, 'true');
        }
    }

    saveUser(user) {
        localStorage.setItem(this.userKey, JSON.stringify(user));
    }

    restoreSession() {
        try {
            // Try session storage first
            let sessionData = sessionStorage.getItem(this.sessionKey);
            
            // If not found, try local storage
            if (!sessionData) {
                sessionData = localStorage.getItem(this.sessionKey);
            }

            if (sessionData) {
                const session = JSON.parse(sessionData);
                
                // Check if session is expired
                if (Date.now() < session.expiresAt) {
                    this.session = session;
                    this.user = JSON.parse(localStorage.getItem(this.userKey) || '{}');
                    
                    // Update last activity
                    this.session.lastActivity = Date.now();
                    this.saveSession(this.session, this.session.rememberMe);
                    
                    console.log('🔄 Session restored for:', this.user.email);
                    return true;
                } else {
                    // Session expired
                    this.clearExpiredSession();
                }
            }
        } catch (error) {
            console.error('Session restore error:', error);
            this.clearExpiredSession();
        }

        return false;
    }

    clearExpiredSession() {
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.userKey);
        localStorage.removeItem(this.sessionKey);
        sessionStorage.removeItem(this.sessionKey);
        localStorage.removeItem(this.rememberKey);
        this.user = null;
        this.session = null;
    }

    // ============================================
    // SESSION AUTO-REFRESH
    // ============================================
    setupAutoRefresh() {
        // Check session every minute
        setInterval(() => {
            if (this.session && this.isAuthenticated()) {
                const timeUntilExpiry = this.session.expiresAt - Date.now();
                
                // Refresh if within threshold
                if (timeUntilExpiry < this.refreshThreshold) {
                    this.refreshSession();
                }
            }
        }, 60000);
    }

    refreshSession() {
        if (!this.session) return;
        
        this.session.expiresAt = Date.now() + this.sessionTimeout;
        this.session.lastActivity = Date.now();
        
        this.saveSession(this.session, this.session.rememberMe);
        console.log('🔄 Session refreshed');
    }

    // ============================================
    // ACTIVITY TRACKING
    // ============================================
    setupActivityTracking() {
        const events = ['click', 'keydown', 'scroll', 'mousemove', 'touchstart'];
        
        const updateActivity = () => {
            if (this.session) {
                this.session.lastActivity = Date.now();
                
                // Save periodically (every 5 minutes)
                const lastSave = parseInt(sessionStorage.getItem('last_session_save') || '0');
                if (Date.now() - lastSave > 300000) {
                    this.saveSession(this.session, this.session.rememberMe);
                    sessionStorage.setItem('last_session_save', Date.now().toString());
                }
            }
        };

        // Throttle to every 30 seconds
        let throttleTimer;
        events.forEach(event => {
            document.addEventListener(event, () => {
                clearTimeout(throttleTimer);
                throttleTimer = setTimeout(updateActivity, 30000);
            }, { passive: true });
        });
    }

    // ============================================
    // AUTHENTICATION CHECKS
    // ============================================
    isAuthenticated() {
        if (!this.session) return false;
        
        // Check expiry
        if (Date.now() > this.session.expiresAt) {
            this.logout();
            return false;
        }

        return true;
    }

    isAdmin() {
        return this.isAuthenticated() && this.user?.role === 'admin';
    }

    isModerator() {
        return this.isAuthenticated() && ['admin', 'moderator'].includes(this.user?.role);
    }

    hasPermission(permission) {
        if (!this.isAuthenticated()) return false;
        if (this.user?.role === 'admin') return true; // Admin has all permissions
        return this.user?.permissions?.includes(permission) || false;
    }

    hasAnyPermission(permissions) {
        return permissions.some(p => this.hasPermission(p));
    }

    hasAllPermissions(permissions) {
        return permissions.every(p => this.hasPermission(p));
    }

    // ============================================
    // SESSION INFORMATION
    // ============================================
    getSessionInfo() {
        if (!this.session) return null;
        
        return {
            sessionId: this.session.id,
            userId: this.session.userId,
            createdAt: new Date(this.session.createdAt).toISOString(),
            expiresAt: new Date(this.session.expiresAt).toISOString(),
            remainingTime: Math.max(0, this.session.expiresAt - Date.now()),
            lastActivity: new Date(this.session.lastActivity).toISOString(),
            rememberMe: this.session.rememberMe || false
        };
    }

    getRemainingTime() {
        if (!this.session) return 0;
        return Math.max(0, this.session.expiresAt - Date.now());
    }

    getSessionExpiry() {
        return this.session ? this.session.expiresAt : null;
    }

    // ============================================
    // PROTECTED ROUTE GUARD
    // ============================================
    guardRoute(requiredRole = null, requiredPermission = null) {
        if (!this.isAuthenticated()) {
            // Save intended URL for redirect after login
            sessionStorage.setItem('intended_url', window.location.href);
            window.location.href = '/login.html';
            return false;
        }

        if (requiredRole && this.user?.role !== requiredRole && this.user?.role !== 'admin') {
            window.location.href = '/403.html';
            return false;
        }

        if (requiredPermission && !this.hasPermission(requiredPermission)) {
            window.location.href = '/403.html';
            return false;
        }

        return true;
    }

    // ============================================
    // TOKEN MANAGEMENT
    // ============================================
    generateToken() {
        return 'tok_' + Date.now().toString(36) + '_' + 
               Math.random().toString(36).substr(2, 15) + 
               Math.random().toString(36).substr(2, 15);
    }

    generateSessionId() {
        return 'sess_' + Date.now().toString(36) + '_' + 
               Math.random().toString(36).substr(2, 9);
    }

    getToken() {
        return localStorage.getItem(this.tokenKey);
    }

    setToken(token) {
        localStorage.setItem(this.tokenKey, token);
    }

    // ============================================
    // ACCOUNT SECURITY
    // ============================================
    changePassword(oldPassword, newPassword) {
        // This would normally call an API
        if (!oldPassword || !newPassword) {
            return { success: false, error: 'Both passwords are required.' };
        }

        if (newPassword.length < 8) {
            return { success: false, error: 'New password must be at least 8 characters.' };
        }

        if (oldPassword === newPassword) {
            return { success: false, error: 'New password must be different.' };
        }

        // Simulate API call
        console.log('🔑 Password changed successfully');
        
        if (window.Logger) {
            Logger.log('password_changed', this.user?.email);
        }

        return { success: true, message: 'Password changed successfully.' };
    }

    setup2FA() {
        // This would normally call an API
        console.log('📱 2FA setup initiated');
        return {
            success: true,
            secret: 'JBSWY3DPEHPK3PXP',
            qrCode: 'data:image/png;base64,...'
        };
    }

    verify2FA(code) {
        // This would normally verify with server
        return code === '123456'; // Demo
    }

    // ============================================
    // LOGIN HISTORY
    // ============================================
    getLoginHistory() {
        const history = JSON.parse(localStorage.getItem('login_history') || '[]');
        return history.slice(0, 20);
    }

    addLoginHistory(entry) {
        const history = this.getLoginHistory();
        history.unshift({
            ...entry,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent.substring(0, 100),
            ip: 'secured'
        });
        localStorage.setItem('login_history', JSON.stringify(history.slice(0, 50)));
    }

    // ============================================
    // DEVICE MANAGEMENT
    // ============================================
    getCurrentDeviceInfo() {
        return {
            browser: this.getBrowserInfo(),
            os: this.getOSInfo(),
            device: this.getDeviceType(),
            screen: `${window.screen.width}x${window.screen.height}`,
            language: navigator.language,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };
    }

    getBrowserInfo() {
        const ua = navigator.userAgent;
        if (ua.includes('Firefox')) return 'Firefox';
        if (ua.includes('Chrome')) return 'Chrome';
        if (ua.includes('Safari')) return 'Safari';
        if (ua.includes('Edge')) return 'Edge';
        return 'Unknown';
    }

    getOSInfo() {
        const ua = navigator.userAgent;
        if (ua.includes('Windows')) return 'Windows';
        if (ua.includes('Mac')) return 'macOS';
        if (ua.includes('Linux')) return 'Linux';
        if (ua.includes('Android')) return 'Android';
        if (ua.includes('iOS')) return 'iOS';
        return 'Unknown';
    }

    getDeviceType() {
        return /Mobile|Android|iPhone|iPad|iPod/.test(navigator.userAgent) ? 'Mobile' : 'Desktop';
    }

    // ============================================
    // CLEANUP
    // ============================================
    destroy() {
        this.logout();
        this.initialized = false;
        console.log('Auth Guard module destroyed');
    }
}

// ============================================
// INITIALIZE GLOBAL AUTH GUARD INSTANCE
// ============================================
window.AuthGuard = new AuthGuard();

// ============================================
// AUTO-PROTECT DASHBOARD & ADMIN PAGES
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    const protectedPaths = ['/dashboard.html', '/admin.html', '/dashboard', '/admin'];
    const currentPath = window.location.pathname;

    if (protectedPaths.some(path => currentPath.endsWith(path))) {
        if (!window.AuthGuard.isAuthenticated()) {
            sessionStorage.setItem('intended_url', window.location.href);
            window.location.href = '/login.html';
        }
    }
});

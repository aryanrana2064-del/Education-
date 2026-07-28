// ============================================
// SECURE WEBSITE — Security Core Module v2.0
// Main Security System Controller
// ============================================

class SecurityCore {
    constructor(config = {}) {
        this.version = '2.0.0';
        this.initialized = false;
        this.attackCount = 0;
        this.blockedRequests = 0;
        this.threatLevel = 'low';
        this.startTime = Date.now();
        this.auditLogs = [];
        this.activeWarnings = [];
        
        this.config = {
            debug: config.debug || false,
            logLevel: config.logLevel || 'warn',
            enableFirewall: config.enableFirewall !== false,
            enableRateLimit: config.enableRateLimit !== false,
            enableCSRF: config.enableCSRF !== false,
            enableXSS: config.enableXSS !== false,
            enableSQLInjection: config.enableSQLInjection !== false,
            maxLoginAttempts: config.maxLoginAttempts || 5,
            lockoutDuration: config.lockoutDuration || 900000,
            sessionTimeout: config.sessionTimeout || 3600000,
            ...config
        };
        
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    init() {
        if (this.initialized) return;
        
        this.log('Security Core v' + this.version + ' initializing...', 'info');
        this.applySecurityHeaders();
        this.setupEventListeners();
        this.startThreatMonitoring();
        this.initialized = true;
        this.log('✅ Security Core initialized successfully', 'info');
    }

    // ============================================
    // SECURITY HEADERS
    // ============================================
    applySecurityHeaders() {
        const metaTags = [
            { httpEquiv: 'Content-Security-Policy', content: "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://www.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https:; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'" },
            { httpEquiv: 'X-Content-Type-Options', content: 'nosniff' },
            { httpEquiv: 'X-Frame-Options', content: 'DENY' },
            { httpEquiv: 'X-XSS-Protection', content: '1; mode=block' },
            { httpEquiv: 'Referrer-Policy', content: 'strict-origin-when-cross-origin' }
        ];

        metaTags.forEach(tag => {
            if (!document.querySelector(`meta[http-equiv="${tag.httpEquiv}"]`)) {
                const meta = document.createElement('meta');
                meta.httpEquiv = tag.httpEquiv;
                meta.content = tag.content;
                document.head.appendChild(meta);
            }
        });
    }

    // ============================================
    // THREAT MONITORING
    // ============================================
    startThreatMonitoring() {
        setInterval(() => {
            this.analyzeThreatLevel();
            this.cleanupOldData();
        }, 30000);
    }

    analyzeThreatLevel() {
        const recentAttacks = this.attackCount;
        if (recentAttacks > 50) this.threatLevel = 'critical';
        else if (recentAttacks > 20) this.threatLevel = 'high';
        else if (recentAttacks > 5) this.threatLevel = 'medium';
        else this.threatLevel = 'low';

        // Decay attack count over time
        if (this.threatLevel === 'low') {
            this.attackCount = Math.max(0, this.attackCount - 1);
        }
    }

    cleanupOldData() {
        const cutoff = Date.now() - 3600000;
        this.auditLogs = this.auditLogs.filter(log => new Date(log.timestamp).getTime() > cutoff);
    }

    // ============================================
    // EVENT LISTENERS
    // ============================================
    setupEventListeners() {
        // Monitor DOM for script injection
        const observer = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === 1) {
                        if (node.tagName === 'SCRIPT' && !node.hasAttribute('data-safe')) {
                            this.log('⚠️ Suspicious script injection blocked', 'warn');
                            node.remove();
                            this.attackCount++;
                        }
                    }
                });
            });
        });

        observer.observe(document.body, { childList: true, subtree: true });

        // Block dev tools shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey && e.shiftKey && ['I', 'J', 'C'].includes(e.key.toUpperCase())) ||
                (e.ctrlKey && ['u', 's'].includes(e.key.toLowerCase())) ||
                e.key === 'F12') {
                e.preventDefault();
                return false;
            }
        });

        // Block right-click on sensitive elements
        document.addEventListener('contextmenu', (e) => {
            if (e.target.closest('[data-protected]')) {
                e.preventDefault();
            }
        });
    }

    // ============================================
    // AUDIT LOGGING
    // ============================================
    audit(action, user = 'anonymous', details = {}) {
        const log = {
            id: this.generateId(),
            timestamp: new Date().toISOString(),
            action,
            user,
            ip: this.getClientIP(),
            userAgent: navigator.userAgent.substring(0, 200),
            success: details.success !== false,
            details: JSON.stringify(details).substring(0, 500)
        };

        this.auditLogs.push(log);
        
        // Keep last 1000 logs
        if (this.auditLogs.length > 1000) {
            this.auditLogs = this.auditLogs.slice(-500);
        }

        // Log to console in debug mode
        if (this.config.debug) {
            console.log(`📝 AUDIT: [${log.timestamp}] ${action} - ${user}`);
        }

        return log;
    }

    getAuditLogs(limit = 50, filter = null) {
        let logs = [...this.auditLogs];
        if (filter) {
            logs = logs.filter(l => l.action.includes(filter) || l.user.includes(filter));
        }
        return logs.slice(-limit).reverse();
    }

    // ============================================
    // THREAT DETECTION
    // ============================================
    detectThreat(request = {}) {
        let score = 0;
        const threats = [];

        // Check URL patterns
        const url = (request.url || window.location.href).toLowerCase();
        if (url.includes('<script') || url.includes('javascript:')) {
            score += 80;
            threats.push('XSS_ATTEMPT');
        }
        if (url.includes("'") || url.includes('"') || url.includes('union') || url.includes('select')) {
            score += 60;
            threats.push('SQL_INJECTION');
        }
        if (url.includes('../') || url.includes('%2e%2e')) {
            score += 50;
            threats.push('PATH_TRAVERSAL');
        }

        // Check request frequency
        const ip = this.getClientIP();
        const recentRequests = this.auditLogs.filter(l => 
            l.details.includes(ip) && 
            new Date(l.timestamp).getTime() > Date.now() - 1000
        ).length;

        if (recentRequests > 20) {
            score += 70;
            threats.push('RAPID_REQUESTS');
        }

        return { score, threats, isThreat: score > 50 };
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================
    getStatus() {
        return {
            version: this.version,
            initialized: this.initialized,
            threatLevel: this.threatLevel,
            attackCount: this.attackCount,
            blockedRequests: this.blockedRequests,
            uptime: Date.now() - this.startTime,
            activeWarnings: this.activeWarnings.length,
            auditLogCount: this.auditLogs.length
        };
    }

    getClientIP() {
        return '127.0.0.1'; // Browser can't get real IP
    }

    generateId() {
        return 'sec_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 9);
    }

    log(message, level = 'info') {
        const levels = { debug: 0, info: 1, warn: 2, error: 3 };
        const configLevel = levels[this.config.logLevel] || 1;
        
        if (levels[level] >= configLevel) {
            const prefix = { debug: '🔍', info: 'ℹ️', warn: '⚠️', error: '❌' }[level] || '📋';
            console.log(`${prefix} [Security] ${message}`);
        }
    }

    addWarning(warning) {
        this.activeWarnings.push({
            ...warning,
            timestamp: new Date().toISOString()
        });
    }

    clearWarnings() {
        this.activeWarnings = [];
    }
}

// ============================================
// INITIALIZE GLOBAL SECURITY INSTANCE
// ============================================
window.Security = new SecurityCore({
    debug: false,
    logLevel: 'warn',
    enableFirewall: true,
    enableRateLimit: true
});

console.log('🛡️ Security Core v' + window.Security.version + ' Loaded');
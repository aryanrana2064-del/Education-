// ============================================
// SECURE WEBSITE — Logger Module v2.0
// Audit Logging, Event Tracking & Monitoring
// ============================================

class Logger {
    constructor() {
        this.logs = [];
        this.maxLogs = 1000;
        this.maxLogSize = 500;
        this.logLevels = {
            debug: 0,
            info: 1,
            warn: 2,
            error: 3,
            critical: 4
        };
        this.currentLevel = this.logLevels.info;
        this.persistToStorage = true;
        this.storageKey = 'secure_audit_logs';
        this.initialized = false;
        
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    init() {
        this.restoreLogs();
        this.setupErrorHandling();
        this.initialized = true;
        console.log('📝 Logger Module Loaded');
    }

    // ============================================
    // MAIN LOG METHOD
    // ============================================
    log(action, user = 'anonymous', details = {}) {
        const entry = {
            id: this.generateId(),
            timestamp: new Date().toISOString(),
            action: this.sanitizeAction(action),
            user: this.sanitizeUser(user),
            level: details.level || 'info',
            category: details.category || 'general',
            ip: this.getClientIP(),
            userAgent: this.getUserAgent(),
            url: window.location.href,
            success: details.success !== false,
            message: details.message || '',
            details: this.sanitizeDetails(details),
            sessionId: this.getSessionId()
        };

        // Add to logs
        this.logs.push(entry);

        // Trim if exceeds max
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(-this.maxLogs / 2);
        }

        // Persist to storage
        if (this.persistToStorage) {
            this.saveLogs();
        }

        // Console output based on level
        this.consoleOutput(entry);

        return entry;
    }

    // ============================================
    // CONVENIENCE METHODS
    // ============================================
    debug(action, user, details = {}) {
        return this.log(action, user, { ...details, level: 'debug' });
    }

    info(action, user, details = {}) {
        return this.log(action, user, { ...details, level: 'info' });
    }

    warn(action, user, details = {}) {
        return this.log(action, user, { ...details, level: 'warn' });
    }

    error(action, user, details = {}) {
        return this.log(action, user, { ...details, level: 'error' });
    }

    critical(action, user, details = {}) {
        return this.log(action, user, { ...details, level: 'critical' });
    }

    // ============================================
    // SPECIALIZED LOGGING
    // ============================================
    logLogin(email, success, details = {}) {
        return this.log(
            success ? 'login_success' : 'login_failed',
            email,
            {
                ...details,
                category: 'authentication',
                level: success ? 'info' : 'warn',
                success
            }
        );
    }

    logSecurityEvent(event, details = {}) {
        return this.log(
            event,
            'security_system',
            {
                ...details,
                category: 'security',
                level: 'warn'
            }
        );
    }

    logPageView(page, details = {}) {
        return this.log(
            'page_view',
            'visitor',
            {
                ...details,
                category: 'analytics',
                level: 'debug',
                page
            }
        );
    }

    logError(error, details = {}) {
        return this.log(
            'error_occurred',
            'system',
            {
                ...details,
                category: 'error',
                level: 'error',
                message: error.message || String(error),
                stack: error.stack?.substring(0, 500)
            }
        );
    }

    logAPIRequest(endpoint, method, status, duration, details = {}) {
        return this.log(
            'api_request',
            'system',
            {
                ...details,
                category: 'api',
                level: status >= 400 ? 'warn' : 'debug',
                endpoint,
                method,
                status,
                duration
            }
        );
    }

    // ============================================
    // QUERY METHODS
    // ============================================
    getLogs(limit = 50, filter = {}) {
        let filtered = [...this.logs];

        // Apply filters
        if (filter.level) {
            filtered = filtered.filter(l => l.level === filter.level);
        }
        if (filter.category) {
            filtered = filtered.filter(l => l.category === filter.category);
        }
        if (filter.user) {
            filtered = filtered.filter(l => l.user.includes(filter.user));
        }
        if (filter.action) {
            filtered = filtered.filter(l => l.action.includes(filter.action));
        }
        if (filter.success !== undefined) {
            filtered = filtered.filter(l => l.success === filter.success);
        }
        if (filter.startDate) {
            filtered = filtered.filter(l => new Date(l.timestamp) >= new Date(filter.startDate));
        }
        if (filter.endDate) {
            filtered = filtered.filter(l => new Date(l.timestamp) <= new Date(filter.endDate));
        }

        // Sort by timestamp descending
        filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        // Limit
        return filtered.slice(0, limit);
    }

    getRecentLogs(minutes = 60) {
        const cutoff = new Date(Date.now() - minutes * 60000);
        return this.logs.filter(l => new Date(l.timestamp) >= cutoff);
    }

    getLogsByUser(user, limit = 50) {
        return this.getLogs(limit, { user });
    }

    getLogsByCategory(category, limit = 50) {
        return this.getLogs(limit, { category });
    }

    getLogsByLevel(level, limit = 50) {
        return this.getLogs(limit, { level });
    }

    getErrorLogs(limit = 50) {
        return this.getLogs(limit, { level: 'error' });
    }

    getSecurityLogs(limit = 50) {
        return this.getLogs(limit, { category: 'security' });
    }

    // ============================================
    // STATISTICS
    // ============================================
    getStats() {
        const now = Date.now();
        const last24h = this.logs.filter(l => now - new Date(l.timestamp).getTime() < 86400000);
        const last1h = this.logs.filter(l => now - new Date(l.timestamp).getTime() < 3600000);

        return {
            totalLogs: this.logs.length,
            logs24h: last24h.length,
            logs1h: last1h.length,
            errorCount: this.logs.filter(l => l.level === 'error' || l.level === 'critical').length,
            warningCount: this.logs.filter(l => l.level === 'warn').length,
            uniqueUsers: new Set(this.logs.map(l => l.user)).size,
            categories: this.getCategoryBreakdown(),
            levels: this.getLevelBreakdown(),
            oldestLog: this.logs[0]?.timestamp || null,
            newestLog: this.logs[this.logs.length - 1]?.timestamp || null
        };
    }

    getCategoryBreakdown() {
        const categories = {};
        this.logs.forEach(l => {
            categories[l.category] = (categories[l.category] || 0) + 1;
        });
        return categories;
    }

    getLevelBreakdown() {
        const levels = {};
        this.logs.forEach(l => {
            levels[l.level] = (levels[l.level] || 0) + 1;
        });
        return levels;
    }

    // ============================================
    // EXPORT
    // ============================================
    exportLogs(format = 'json') {
        switch (format) {
            case 'json':
                return JSON.stringify(this.logs, null, 2);
            case 'csv':
                return this.exportToCSV();
            case 'text':
                return this.exportToText();
            default:
                return JSON.stringify(this.logs);
        }
    }

    exportToCSV() {
        const headers = ['Timestamp', 'Action', 'User', 'Level', 'Category', 'Success', 'Message', 'IP', 'URL'];
        const rows = this.logs.map(l => [
            l.timestamp,
            l.action,
            l.user,
            l.level,
            l.category,
            l.success,
            l.message,
            l.ip,
            l.url
        ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));

        return [headers.join(','), ...rows].join('\n');
    }

    exportToText() {
        return this.logs.map(l => 
            `[${l.timestamp}] [${l.level.toUpperCase()}] ${l.action} - User: ${l.user} - ${l.message}`
        ).join('\n');
    }

    downloadLogs(format = 'json') {
        const content = this.exportLogs(format);
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit_logs_${new Date().toISOString().slice(0, 10)}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // ============================================
    // CLEANUP
    // ============================================
    clearLogs(olderThan = null) {
        if (olderThan) {
            const cutoff = new Date(olderThan).getTime();
            this.logs = this.logs.filter(l => new Date(l.timestamp).getTime() >= cutoff);
        } else {
            this.logs = [];
        }
        this.saveLogs();
        console.log('🗑️ Logs cleared');
    }

    clearOldLogs(daysToKeep = 30) {
        const cutoff = Date.now() - daysToKeep * 86400000;
        const before = this.logs.length;
        this.logs = this.logs.filter(l => new Date(l.timestamp).getTime() >= cutoff);
        const removed = before - this.logs.length;
        this.saveLogs();
        console.log(`🗑️ Removed ${removed} old logs (older than ${daysToKeep} days)`);
        return removed;
    }

    // ============================================
    // PERSISTENCE
    // ============================================
    saveLogs() {
        try {
            const toSave = this.logs.slice(-this.maxLogSize);
            localStorage.setItem(this.storageKey, JSON.stringify(toSave));
        } catch (error) {
            console.error('Failed to save logs:', error);
            // If storage full, clear old logs
            this.clearOldLogs(7);
        }
    }

    restoreLogs() {
        try {
            const saved = localStorage.getItem(this.storageKey);
            if (saved) {
                this.logs = JSON.parse(saved);
                console.log(`📝 Restored ${this.logs.length} audit logs`);
            }
        } catch (error) {
            console.error('Failed to restore logs:', error);
            this.logs = [];
        }
    }

    // ============================================
    // ERROR HANDLING
    // ============================================
    setupErrorHandling() {
        // Global error handler
        window.addEventListener('error', (event) => {
            this.logError(event.error || event.message, {
                filename: event.filename,
                lineno: event.lineno,
                colno: event.colno
            });
        });

        // Unhandled promise rejection
        window.addEventListener('unhandledrejection', (event) => {
            this.logError(event.reason || 'Unhandled Promise Rejection', {
                type: 'unhandled_rejection'
            });
        });
    }

    // ============================================
    // SANITIZATION
    // ============================================
    sanitizeAction(action) {
        if (!action) return 'unknown';
        return String(action).substring(0, 100).replace(/[<>"'`]/g, '');
    }

    sanitizeUser(user) {
        if (!user) return 'anonymous';
        return String(user).substring(0, 100).replace(/[<>"'`]/g, '');
    }

    sanitizeDetails(details) {
        try {
            const str = JSON.stringify(details);
            return str.substring(0, this.maxLogSize);
        } catch {
            return String(details).substring(0, this.maxLogSize);
        }
    }

    // ============================================
    // UTILITIES
    // ============================================
    generateId() {
        return 'log_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 9);
    }

    getClientIP() {
        return 'client_side';
    }

    getUserAgent() {
        return navigator.userAgent.substring(0, 200);
    }

    getSessionId() {
        return sessionStorage.getItem('session_id') || 'no_session';
    }

    consoleOutput(entry) {
        const prefix = {
            debug: '🔍',
            info: 'ℹ️',
            warn: '⚠️',
            error: '❌',
            critical: '🚨'
        }[entry.level] || '📋';

        if (this.logLevels[entry.level] >= this.currentLevel) {
            const message = `${prefix} [${entry.timestamp}] ${entry.action} - ${entry.user}`;
            
            switch (entry.level) {
                case 'error':
                case 'critical':
                    console.error(message);
                    break;
                case 'warn':
                    console.warn(message);
                    break;
                default:
                    console.log(message);
            }
        }
    }

    setLogLevel(level) {
        if (this.logLevels[level] !== undefined) {
            this.currentLevel = this.logLevels[level];
        }
    }

    // ============================================
    // CLEANUP
    // ============================================
    destroy() {
        this.saveLogs();
        this.initialized = false;
        console.log('Logger module destroyed');
    }
}

// ============================================
// INITIALIZE GLOBAL LOGGER INSTANCE
// ============================================
window.Logger = new Logger();

// Log page view
window.Logger.logPageView(window.location.pathname);
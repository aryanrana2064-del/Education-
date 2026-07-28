// ============================================
// SECURE WEBSITE — Firewall Module v2.0
// DDoS Protection & Bot Detection
// ============================================

class Firewall {
    constructor() {
        this.blocked = new Set();
        this.suspicious = new Map();
        this.whitelist = new Set([
            '127.0.0.1',
            'localhost',
            '::1'
        ]);
        this.requestLog = new Map();
        this.threatScores = new Map();
        this.blockedCount = 0;
        this.banDuration = 3600000; // 1 hour
        this.attackThreshold = 50;
        this.cleanupInterval = null;
        
        this.blockedUserAgents = [
            'sqlmap', 'nikto', 'nmap', 'nessus', 'openvas',
            'acunetix', 'netsparker', 'burp', 'zap', 'w3af',
            'metasploit', 'hydra', 'medusa', 'dirbuster', 'gobuster'
        ];
        
        this.searchEngines = [
            'googlebot', 'bingbot', 'duckduckbot',
            'yandexbot', 'slurp', 'baiduspider', 'applebot'
        ];
        
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    init() {
        this.startCleanupInterval();
        console.log('🔥 Firewall Module Loaded');
    }

    // ============================================
    // MAIN FIREWALL CHECK
    // ============================================
    analyze(request = {}) {
        const ip = request.ip || 'unknown';
        const userAgent = (request.userAgent || navigator.userAgent || '').toLowerCase();
        const url = (request.url || window.location.href).toLowerCase();
        const method = (request.method || 'GET').toUpperCase();

        // 1. Check whitelist
        if (this.whitelist.has(ip)) {
            return { allowed: true, reason: 'whitelisted' };
        }

        // 2. Check blocked list
        if (this.blocked.has(ip)) {
            this.blockedCount++;
            return { allowed: false, reason: 'IP blocked', code: 403 };
        }

        // 3. Check user agent
        if (!userAgent || userAgent.length < 5) {
            return { allowed: false, reason: 'Invalid user agent', code: 403 };
        }

        // 4. Check for malicious bots
        if (this.isBlockedBot(userAgent)) {
            this.blockIP(ip, 'Malicious bot detected');
            return { allowed: false, reason: 'Bot blocked', code: 403 };
        }

        // 5. Check request method
        if (!['GET', 'POST', 'HEAD'].includes(method)) {
            this.logSuspicious(ip, 'Invalid method: ' + method);
            return { allowed: false, reason: 'Method not allowed', code: 405 };
        }

        // 6. Check URL for attacks
        const urlCheck = this.checkURL(url);
        if (!urlCheck.safe) {
            this.logSuspicious(ip, urlCheck.reason);
            return { allowed: false, reason: urlCheck.reason, code: 403 };
        }

        // 7. Rate limit check
        if (this.isRateLimited(ip)) {
            this.blockedCount++;
            return { allowed: false, reason: 'Rate limit exceeded', code: 429 };
        }

        // 8. Calculate threat score
        const score = this.calculateThreatScore(ip, userAgent, url);
        if (score > 70) {
            this.blockIP(ip, 'High threat score: ' + score);
            return { allowed: false, reason: 'Security threat', code: 403 };
        }

        // 9. Log request
        this.logRequest(ip);

        return { allowed: true, score };
    }

    // ============================================
    // URL SECURITY CHECK
    // ============================================
    checkURL(url) {
        // SQL Injection patterns
        const sqlPatterns = [
            /union\s+select/i, /select\s+.*from/i,
            /insert\s+into/i, /drop\s+table/i,
            /delete\s+from/i, /update\s+.*set/i,
            /';\s*--/, /"\s*--/, /or\s+1\s*=\s*1/i,
            /exec\s*\(/i, /execute\s*\(/i
        ];

        // XSS patterns
        const xssPatterns = [
            /<script/i, /javascript:/i,
            /on\w+\s*=/i, /<iframe/i,
            /<embed/i, /<object/i,
            /<link/i, /<meta/i,
            /expression\s*\(/i, /eval\s*\(/i
        ];

        // Path traversal
        const pathPatterns = [
            /\.\.\//, /%2e%2e%2f/i,
            /etc\/passwd/i, /boot\.ini/i,
            /win\.ini/i, /\.\.\\/
        ];

        // Check all patterns
        for (const pattern of sqlPatterns) {
            if (pattern.test(url)) {
                return { safe: false, reason: 'SQL Injection attempt blocked' };
            }
        }

        for (const pattern of xssPatterns) {
            if (pattern.test(url)) {
                return { safe: false, reason: 'XSS attack blocked' };
            }
        }

        for (const pattern of pathPatterns) {
            if (pattern.test(url)) {
                return { safe: false, reason: 'Path traversal blocked' };
            }
        }

        // Check for common attack paths
        const blockedPaths = [
            '/wp-admin', '/wp-login', '/phpmyadmin',
            '/adminer', '/.env', '/.git', '/config',
            '/backup', '/sql', '/db', '/dump'
        ];

        for (const path of blockedPaths) {
            if (url.includes(path)) {
                return { safe: false, reason: 'Restricted path accessed' };
            }
        }

        return { safe: true };
    }

    // ============================================
    // BOT DETECTION
    // ============================================
    isBlockedBot(userAgent) {
        // Check blocked list
        for (const blocked of this.blockedUserAgents) {
            if (userAgent.includes(blocked)) return true;
        }

        // Check if it's a bot but not search engine
        const botIndicators = ['bot', 'crawler', 'spider', 'scraper'];
        const isBot = botIndicators.some(ind => userAgent.includes(ind));
        const isSearchEngine = this.searchEngines.some(se => userAgent.includes(se));

        return isBot && !isSearchEngine;
    }

    // ============================================
    // RATE LIMITING
    // ============================================
    isRateLimited(ip) {
        const requests = this.requestLog.get(ip) || [];
        const now = Date.now();
        const recent = requests.filter(t => now - t < 60000); // 1 minute window
        return recent.length > this.attackThreshold;
    }

    logRequest(ip) {
        const requests = this.requestLog.get(ip) || [];
        requests.push(Date.now());
        
        // Keep only last 200 timestamps
        if (requests.length > 200) {
            requests.splice(0, requests.length - 200);
        }
        
        this.requestLog.set(ip, requests);
    }

    // ============================================
    // THREAT SCORE CALCULATION
    // ============================================
    calculateThreatScore(ip, userAgent, url) {
        let score = 0;

        // Check suspicious IP history
        const suspicious = this.suspicious.get(ip);
        if (suspicious) {
            score += suspicious.count * 10;
        }

        // Check request frequency
        const requests = this.requestLog.get(ip) || [];
        const recentCount = requests.filter(t => Date.now() - t < 10000).length;
        if (recentCount > 20) score += 30;
        if (recentCount > 50) score += 50;

        // Check URL complexity
        if (url.length > 500) score += 20;
        if ((url.match(/[?&]/g) || []).length > 10) score += 15;

        return Math.min(score, 100);
    }

    // ============================================
    // IP MANAGEMENT
    // ============================================
    blockIP(ip, reason = 'Security violation') {
        if (this.whitelist.has(ip)) return;
        
        this.blocked.add(ip);
        this.blockedCount++;
        
        console.log(`🚫 Firewall blocked IP: ${ip} — ${reason}`);
        
        // Auto-unblock after ban duration
        setTimeout(() => {
            this.blocked.delete(ip);
            console.log(`🔓 IP auto-unblocked: ${ip}`);
        }, this.banDuration);

        // Log to security core
        if (window.Security) {
            Security.audit('ip_blocked', 'firewall', { ip, reason });
        }
    }

    unblockIP(ip) {
        this.blocked.delete(ip);
        console.log(`🔓 IP manually unblocked: ${ip}`);
        
        if (window.Security) {
            Security.audit('ip_unblocked', 'admin', { ip });
        }
    }

    logSuspicious(ip, reason) {
        const record = this.suspicious.get(ip) || { count: 0, reasons: [] };
        record.count++;
        record.reasons.push({ time: new Date().toISOString(), reason });
        
        if (record.count >= 5) {
            this.blockIP(ip, 'Multiple suspicious activities');
        }
        
        this.suspicious.set(ip, record);
    }

    // ============================================
    // FIREWALL STATISTICS
    // ============================================
    getStats() {
        return {
            blockedIPs: this.blocked.size,
            suspiciousIPs: this.suspicious.size,
            totalRequests: Array.from(this.requestLog.values())
                .reduce((sum, reqs) => sum + reqs.length, 0),
            blockedCount: this.blockedCount,
            whitelistedIPs: this.whitelist.size
        };
    }

    getBlockedIPs() {
        return Array.from(this.blocked);
    }

    getSuspiciousIPs() {
        const result = [];
        this.suspicious.forEach((value, key) => {
            result.push({ ip: key, ...value });
        });
        return result;
    }

    // ============================================
    // CLEANUP
    // ============================================
    startCleanupInterval() {
        this.cleanupInterval = setInterval(() => {
            const now = Date.now();
            
            // Cleanup old request logs
            this.requestLog.forEach((timestamps, ip) => {
                const recent = timestamps.filter(t => now - t < 3600000);
                if (recent.length === 0) {
                    this.requestLog.delete(ip);
                } else {
                    this.requestLog.set(ip, recent);
                }
            });
            
            // Cleanup old suspicious records
            this.suspicious.forEach((record, ip) => {
                record.reasons = record.reasons.filter(r => 
                    now - new Date(r.time).getTime() < 86400000
                );
                if (record.reasons.length === 0 && record.count < 3) {
                    this.suspicious.delete(ip);
                }
            });
        }, 300000); // Every 5 minutes
    }

    // ============================================
    // EMERGENCY MODE
    // ============================================
    enableEmergencyMode() {
        this.attackThreshold = 5; // Very strict
        this.banDuration = 86400000; // 24 hours
        console.warn('🚨 FIREWALL EMERGENCY MODE ACTIVATED');
        
        if (window.Security) {
            Security.audit('emergency_mode', 'firewall', { action: 'activated' });
        }
    }

    disableEmergencyMode() {
        this.attackThreshold = 50;
        this.banDuration = 3600000;
        console.log('✅ Firewall emergency mode deactivated');
    }

    // ============================================
    // CLEANUP
    // ============================================
    destroy() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        this.blocked.clear();
        this.suspicious.clear();
        this.requestLog.clear();
        console.log('Firewall module destroyed');
    }
}

// ============================================
// INITIALIZE GLOBAL FIREWALL INSTANCE
// ============================================
window.Firewall = new Firewall();
// ============================================
// SECURE WEBSITE — Rate Limiter Module v2.0
// Request Throttling & Abuse Prevention
// ============================================

class RateLimiter {
    constructor() {
        this.store = new Map();
        this.blockedKeys = new Map();
        this.whitelist = new Set(['127.0.0.1', 'localhost']);
        
        // Default limits
        this.defaultLimit = 100;
        this.defaultWindow = 60000; // 1 minute
        this.blockDuration = 900000; // 15 minutes
        
        // Specific limits for different endpoints
        this.limits = {
            'login': { max: 5, window: 300000, block: 900000 },     // 5 attempts per 5 min
            'api': { max: 60, window: 60000, block: 300000 },        // 60 requests per min
            'search': { max: 30, window: 60000, block: 120000 },     // 30 searches per min
            'upload': { max: 10, window: 300000, block: 600000 },    // 10 uploads per 5 min
            'password_reset': { max: 3, window: 3600000, block: 7200000 }, // 3 per hour
            'contact': { max: 5, window: 3600000, block: 3600000 },  // 5 per hour
            'default': { max: 100, window: 60000, block: 900000 }
        };
        
        this.cleanupInterval = null;
        this.totalBlocked = 0;
        this.totalRequests = 0;
        
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    init() {
        this.startCleanup();
        console.log('⚡ Rate Limiter Module Loaded');
    }

    // ============================================
    // MAIN RATE LIMIT CHECK
    // ============================================
    check(key, limit = null, windowMs = null, endpoint = 'default') {
        // Check whitelist
        if (this.whitelist.has(key)) {
            return { allowed: true, remaining: Infinity, resetIn: 0 };
        }

        // Check if blocked
        if (this.isBlocked(key)) {
            const blockInfo = this.blockedKeys.get(key);
            const remainingBlock = Math.ceil((blockInfo.blockedUntil - Date.now()) / 1000);
            return {
                allowed: false,
                reason: 'Rate limit exceeded. Temporary block active.',
                retryAfter: remainingBlock,
                blockedUntil: new Date(blockInfo.blockedUntil).toISOString()
            };
        }

        // Get endpoint-specific or default limits
        const endpointLimits = this.limits[endpoint] || this.limits.default;
        const effectiveLimit = limit || endpointLimits.max;
        const effectiveWindow = windowMs || endpointLimits.window;

        // Get or create record
        const now = Date.now();
        let record = this.store.get(key);
        
        if (!record) {
            record = { timestamps: [], totalCount: 0, firstRequest: now };
            this.store.set(key, record);
        }

        // Clean old timestamps
        record.timestamps = record.timestamps.filter(t => now - t < effectiveWindow);

        // Check if limit exceeded
        if (record.timestamps.length >= effectiveLimit) {
            // Block the key
            const blockDuration = endpointLimits.block || this.blockDuration;
            this.blockKey(key, blockDuration);
            
            this.totalBlocked++;
            
            console.warn(`🚫 Rate limit exceeded for: ${key} (${endpoint})`);
            
            return {
                allowed: false,
                reason: 'Rate limit exceeded.',
                retryAfter: Math.ceil(blockDuration / 1000),
                blockedUntil: new Date(now + blockDuration).toISOString()
            };
        }

        // Add timestamp
        record.timestamps.push(now);
        record.totalCount++;
        this.totalRequests++;

        // Calculate remaining
        const remaining = effectiveLimit - record.timestamps.length;
        const oldestTimestamp = record.timestamps[0];
        const resetIn = Math.ceil((oldestTimestamp + effectiveWindow - now) / 1000);

        return {
            allowed: true,
            remaining,
            resetIn: Math.max(0, resetIn),
            totalRequests: record.totalCount
        };
    }

    // ============================================
    // BLOCK MANAGEMENT
    // ============================================
    blockKey(key, duration = this.blockDuration) {
        this.blockedKeys.set(key, {
            blockedAt: Date.now(),
            blockedUntil: Date.now() + duration,
            duration: duration
        });

        // Auto-unblock after duration
        setTimeout(() => {
            this.unblockKey(key);
        }, duration);
    }

    unblockKey(key) {
        this.blockedKeys.delete(key);
        console.log(`🔓 Unblocked: ${key}`);
    }

    isBlocked(key) {
        if (!this.blockedKeys.has(key)) return false;
        
        const blockInfo = this.blockedKeys.get(key);
        if (Date.now() > blockInfo.blockedUntil) {
            this.blockedKeys.delete(key);
            return false;
        }
        
        return true;
    }

    // ============================================
    // SPECIFIC ENDPOINT CHECKS
    // ============================================
    checkLogin(key) {
        return this.check(key, null, null, 'login');
    }

    checkAPI(key) {
        return this.check(key, null, null, 'api');
    }

    checkSearch(key) {
        return this.check(key, null, null, 'search');
    }

    checkUpload(key) {
        return this.check(key, null, null, 'upload');
    }

    checkPasswordReset(key) {
        return this.check(key, null, null, 'password_reset');
    }

    checkContact(key) {
        return this.check(key, null, null, 'contact');
    }

    // ============================================
    // KEY MANAGEMENT
    // ============================================
    reset(key) {
        this.store.delete(key);
        this.blockedKeys.delete(key);
    }

    resetAll() {
        this.store.clear();
        this.blockedKeys.clear();
        this.totalBlocked = 0;
        this.totalRequests = 0;
        console.log('🔄 All rate limits reset');
    }

    addToWhitelist(key) {
        this.whitelist.add(key);
    }

    removeFromWhitelist(key) {
        this.whitelist.delete(key);
    }

    // ============================================
    // STATISTICS
    // ============================================
    getStats() {
        return {
            activeKeys: this.store.size,
            blockedKeys: this.blockedKeys.size,
            whitelistedKeys: this.whitelist.size,
            totalBlocked: this.totalBlocked,
            totalRequests: this.totalRequests,
            uptime: process.uptime ? process.uptime() : 0
        };
    }

    getKeyInfo(key) {
        const record = this.store.get(key);
        const blocked = this.blockedKeys.get(key);
        
        return {
            key,
            isWhitelisted: this.whitelist.has(key),
            isBlocked: this.isBlocked(key),
            blockedInfo: blocked ? {
                blockedAt: new Date(blocked.blockedAt).toISOString(),
                blockedUntil: new Date(blocked.blockedUntil).toISOString(),
                remaining: Math.max(0, Math.ceil((blocked.blockedUntil - Date.now()) / 1000))
            } : null,
            requests: record ? {
                count: record.timestamps.length,
                totalCount: record.totalCount,
                firstRequest: new Date(record.firstRequest).toISOString()
            } : null
        };
    }

    getAllActiveKeys() {
        const keys = [];
        this.store.forEach((record, key) => {
            keys.push({
                key,
                requestCount: record.timestamps.length,
                totalCount: record.totalCount,
                isBlocked: this.isBlocked(key)
            });
        });
        return keys.sort((a, b) => b.requestCount - a.requestCount);
    }

    getBlockedKeys() {
        const keys = [];
        this.blockedKeys.forEach((info, key) => {
            keys.push({
                key,
                blockedAt: new Date(info.blockedAt).toISOString(),
                blockedUntil: new Date(info.blockedUntil).toISOString(),
                remainingSeconds: Math.max(0, Math.ceil((info.blockedUntil - Date.now()) / 1000))
            });
        });
        return keys;
    }

    // ============================================
    // CLEANUP
    // ============================================
    startCleanup() {
        this.cleanupInterval = setInterval(() => {
            const now = Date.now();
            
            // Clean old request records
            this.store.forEach((record, key) => {
                // Remove timestamps older than 1 hour
                record.timestamps = record.timestamps.filter(t => now - t < 3600000);
                
                // Remove empty records
                if (record.timestamps.length === 0 && now - record.firstRequest > 3600000) {
                    this.store.delete(key);
                }
            });

            // Clean expired blocks
            this.blockedKeys.forEach((info, key) => {
                if (now > info.blockedUntil) {
                    this.blockedKeys.delete(key);
                }
            });
        }, 300000); // Every 5 minutes
    }

    // ============================================
    // CONFIGURATION
    // ============================================
    updateLimit(endpoint, max, windowMs, blockMs) {
        this.limits[endpoint] = {
            max: max || this.limits[endpoint]?.max || 100,
            window: windowMs || this.limits[endpoint]?.window || 60000,
            block: blockMs || this.limits[endpoint]?.block || 900000
        };
        console.log(`⚙️ Updated limits for: ${endpoint}`);
    }

    setDefaultLimit(max, windowMs) {
        this.defaultLimit = max || this.defaultLimit;
        this.defaultWindow = windowMs || this.defaultWindow;
    }

    // ============================================
    // EMERGENCY MODE
    // ============================================
    enableStrictMode() {
        // Reduce all limits by 80%
        Object.keys(this.limits).forEach(endpoint => {
            this.limits[endpoint].max = Math.max(1, Math.floor(this.limits[endpoint].max * 0.2));
            this.limits[endpoint].window = this.limits[endpoint].window * 2;
        });
        console.warn('⚠️ Rate limiter strict mode enabled');
    }

    disableStrictMode() {
        // Restore defaults
        this.limits = {
            'login': { max: 5, window: 300000, block: 900000 },
            'api': { max: 60, window: 60000, block: 300000 },
            'search': { max: 30, window: 60000, block: 120000 },
            'upload': { max: 10, window: 300000, block: 600000 },
            'password_reset': { max: 3, window: 3600000, block: 7200000 },
            'contact': { max: 5, window: 3600000, block: 3600000 },
            'default': { max: 100, window: 60000, block: 900000 }
        };
        console.log('✅ Rate limiter normal mode restored');
    }

    // ============================================
    // CLEANUP
    // ============================================
    destroy() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        this.store.clear();
        this.blockedKeys.clear();
        this.whitelist.clear();
        console.log('Rate Limiter module destroyed');
    }
}

// ============================================
// INITIALIZE GLOBAL RATE LIMITER INSTANCE
// ============================================
window.RateLimiter = new RateLimiter();
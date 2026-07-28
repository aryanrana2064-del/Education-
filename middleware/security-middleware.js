// ============================================
// SECURE WEBSITE — Security Middleware v2.0
// Request Security, Sanitization & Validation
// ============================================

export default async function securityMiddleware(req, res, next) {
    try {
        // ============================================
        // 1. APPLY SECURITY HEADERS
        // ============================================
        applySecurityHeaders(res);

        // ============================================
        // 2. VALIDATE REQUEST METHOD
        // ============================================
        const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
        if (!allowedMethods.includes(req.method)) {
            return res.status(405).json({
                success: false,
                error: 'Method not allowed',
                code: 'METHOD_NOT_ALLOWED'
            });
        }

        // ============================================
        // 3. CHECK REQUEST SIZE
        // ============================================
        const maxSize = 10 * 1024 * 1024; // 10MB
        const contentLength = parseInt(req.headers['content-length'] || '0');
        
        if (contentLength > maxSize) {
            return res.status(413).json({
                success: false,
                error: 'Request too large',
                code: 'PAYLOAD_TOO_LARGE',
                message: `Maximum request size is ${maxSize / 1024 / 1024}MB.`
            });
        }

        // ============================================
        // 4. VALIDATE CONTENT TYPE
        // ============================================
        if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
            const contentType = req.headers['content-type'] || '';
            
            if (contentLength > 0 && !contentType.includes('application/json') && 
                !contentType.includes('multipart/form-data') && 
                !contentType.includes('application/x-www-form-urlencoded')) {
                return res.status(415).json({
                    success: false,
                    error: 'Unsupported media type',
                    code: 'UNSUPPORTED_MEDIA_TYPE'
                });
            }
        }

        // ============================================
        // 5. SANITIZE REQUEST BODY
        // ============================================
        if (req.body && typeof req.body === 'object') {
            req.body = sanitizeObject(req.body);
        }

        // ============================================
        // 6. SANITIZE QUERY PARAMETERS
        // ============================================
        if (req.query && typeof req.query === 'object') {
            req.query = sanitizeObject(req.query);
        }

        // ============================================
        // 7. SANITIZE URL PARAMETERS
        // ============================================
        if (req.params && typeof req.params === 'object') {
            req.params = sanitizeObject(req.params);
        }

        // ============================================
        // 8. CHECK FOR SQL INJECTION
        // ============================================
        const sqlInjectionFound = checkForSQLInjection(req);
        if (sqlInjectionFound) {
            console.warn(`🚨 SQL Injection attempt blocked from IP: ${getClientIP(req)}`);
            
            return res.status(403).json({
                success: false,
                error: 'Malicious request blocked',
                code: 'SQL_INJECTION_BLOCKED'
            });
        }

        // ============================================
        // 9. CHECK FOR XSS ATTEMPTS
        // ============================================
        const xssFound = checkForXSS(req);
        if (xssFound) {
            console.warn(`🚨 XSS attempt blocked from IP: ${getClientIP(req)}`);
            
            return res.status(403).json({
                success: false,
                error: 'Malicious request blocked',
                code: 'XSS_BLOCKED'
            });
        }

        // ============================================
        // 10. VALIDATE CSRF TOKEN (for state-changing requests)
        // ============================================
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
            const csrfToken = req.headers['x-csrf-token'] || req.body?._csrf;
            const sessionToken = req.cookies?.csrf_token;
            
            if (!csrfToken || csrfToken !== sessionToken) {
                return res.status(403).json({
                    success: false,
                    error: 'CSRF validation failed',
                    code: 'CSRF_INVALID'
                });
            }
        }

        // ============================================
        // 11. RATE LIMITING CHECK
        // ============================================
        const clientIP = getClientIP(req);
        const rateLimitKey = `rate_${clientIP}_${req.path}`;
        
        // Simple in-memory rate limiting (use Redis in production)
        if (!checkRateLimit(rateLimitKey, 100, 60000)) {
            return res.status(429).json({
                success: false,
                error: 'Too many requests',
                code: 'RATE_LIMITED',
                retryAfter: 60
            });
        }

        // ============================================
        // 12. ADD REQUEST ID
        // ============================================
        req.requestId = generateRequestId();
        res.setHeader('X-Request-ID', req.requestId);

        // ============================================
        // 13. ADD SECURITY HEADERS TO RESPONSE
        // ============================================
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('X-Response-Time', Date.now().toString());

        // ============================================
        // 14. LOG REQUEST
        // ============================================
        console.log(`🛡️ [${req.requestId}] ${req.method} ${req.path} — IP: ${clientIP}`);

        // ============================================
        // 15. PROCEED TO NEXT MIDDLEWARE
        // ============================================
        next();

    } catch (error) {
        console.error('Security Middleware Error:', error);
        
        return res.status(500).json({
            success: false,
            error: 'Security check failed',
            code: 'SECURITY_ERROR'
        });
    }
}

// ============================================
// SECURITY HEADERS
// ============================================
function applySecurityHeaders(res) {
    const headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Cache-Control': 'no-store, max-age=0',
        'Server': 'CloudShield'
    };

    Object.entries(headers).forEach(([key, value]) => {
        res.setHeader(key, value);
    });
}

// ============================================
// INPUT SANITIZATION
// ============================================
function sanitizeString(str) {
    if (typeof str !== 'string') return str;
    
    return str
        .replace(/<[^>]*>/g, '')           // Remove HTML tags
        .replace(/javascript:/gi, '')       // Remove javascript: URLs
        .replace(/on\w+\s*=/gi, '')         // Remove event handlers
        .replace(/['";]/g, '')              // Remove SQL quotes
        .replace(/--/g, '')                 // Remove SQL comments
        .replace(/\/\*/g, '')               // Remove block comments
        .replace(/\*\//g, '')               // Remove block comments end
        .trim()
        .substring(0, 5000);                // Limit length
}

function sanitizeObject(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;

    const sanitized = Array.isArray(obj) ? [] : {};

    for (const [key, value] of Object.entries(obj)) {
        const cleanKey = sanitizeString(key);
        
        if (typeof value === 'string') {
            sanitized[cleanKey] = sanitizeString(value);
        } else if (typeof value === 'object' && value !== null) {
            sanitized[cleanKey] = sanitizeObject(value);
        } else {
            sanitized[cleanKey] = value;
        }
    }

    return sanitized;
}

// ============================================
// SQL INJECTION DETECTION
// ============================================
function checkForSQLInjection(req) {
    const patterns = [
        /(\bunion\b.*\bselect\b)/i,
        /(\binsert\b.*\binto\b)/i,
        /(\bdrop\b.*\btable\b)/i,
        /(\bdelete\b.*\bfrom\b)/i,
        /(\bupdate\b.*\bset\b)/i,
        /(';\s*--)/,
        /(\bexec\b.*\()/i,
        /(\bexecute\b.*\()/i,
        /(\btruncate\b.*\btable\b)/i,
        /(\balter\b.*\btable\b)/i
    ];

    const checkValue = (value) => {
        if (typeof value === 'string') {
            return patterns.some(p => p.test(value));
        }
        if (typeof value === 'object' && value !== null) {
            return Object.values(value).some(v => checkValue(v));
        }
        return false;
    };

    return checkValue(req.body) || checkValue(req.query) || checkValue(req.params);
}

// ============================================
// XSS DETECTION
// ============================================
function checkForXSS(req) {
    const patterns = [
        /<script\b[^>]*>/i,
        /javascript\s*:/i,
        /on\w+\s*=\s*["']?[^"'>]*["']?/i,
        /<iframe\b[^>]*>/i,
        /<embed\b[^>]*>/i,
        /<object\b[^>]*>/i,
        /<link\b[^>]*>/i,
        /expression\s*\(/i,
        /eval\s*\(/i,
        /document\.cookie/i,
        /document\.write/i
    ];

    const checkValue = (value) => {
        if (typeof value === 'string') {
            return patterns.some(p => p.test(value));
        }
        if (typeof value === 'object' && value !== null) {
            return Object.values(value).some(v => checkValue(v));
        }
        return false;
    };

    return checkValue(req.body) || checkValue(req.query) || checkValue(req.params);
}

// ============================================
// RATE LIMITING (In-Memory)
// ============================================
const rateLimitStore = new Map();

function checkRateLimit(key, limit = 100, windowMs = 60000) {
    const now = Date.now();
    const record = rateLimitStore.get(key) || [];
    const recent = record.filter(t => now - t < windowMs);

    if (recent.length >= limit) return false;

    recent.push(now);
    rateLimitStore.set(key, recent);
    return true;
}

// Clean old entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    rateLimitStore.forEach((timestamps, key) => {
        const recent = timestamps.filter(t => now - t < 300000);
        if (recent.length === 0) rateLimitStore.delete(key);
        else rateLimitStore.set(key, recent);
    });
}, 300000);

// ============================================
// UTILITIES
// ============================================
function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.socket?.remoteAddress || 
           'unknown';
}

function generateRequestId() {
    return 'req_' + Date.now().toString(36) + '_' + 
           Math.random().toString(36).substring(2, 9);
}
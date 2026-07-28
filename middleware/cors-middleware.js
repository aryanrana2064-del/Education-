// ============================================
// SECURE WEBSITE — CORS Middleware v2.0
// Cross-Origin Resource Sharing Configuration
// ============================================

export default async function corsMiddleware(req, res, next) {
    try {
        // ============================================
        // 1. GET REQUEST ORIGIN
        // ============================================
        const requestOrigin = req.headers.origin || req.headers.referer?.split('/').slice(0, 3).join('/');

        // ============================================
        // 2. LOAD ALLOWED ORIGINS
        // ============================================
        const allowedOrigins = getAllowedOrigins();

        // ============================================
        // 3. CHECK IF ORIGIN IS ALLOWED
        // ============================================
        const isAllowed = isOriginAllowed(requestOrigin, allowedOrigins);

        // ============================================
        // 4. SET CORS HEADERS
        // ============================================
        if (isAllowed && requestOrigin) {
            // Reflect the exact origin
            res.setHeader('Access-Control-Allow-Origin', requestOrigin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        } else if (allowedOrigins.includes('*')) {
            // Wildcard — no credentials
            res.setHeader('Access-Control-Allow-Origin', '*');
        } else if (isAllowed) {
            // Use first allowed origin
            res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0]);
        } else {
            // Block — set to null
            res.setHeader('Access-Control-Allow-Origin', 'null');
        }

        // ============================================
        // 5. ALLOWED METHODS
        // ============================================
        const allowedMethods = [
            'GET',
            'POST',
            'PUT',
            'DELETE',
            'PATCH',
            'OPTIONS'
        ].join(', ');

        res.setHeader('Access-Control-Allow-Methods', allowedMethods);

        // ============================================
        // 6. ALLOWED HEADERS
        // ============================================
        const allowedHeaders = [
            'Content-Type',
            'Authorization',
            'X-CSRF-Token',
            'X-Requested-With',
            'X-Request-ID',
            'X-Client-Version',
            'Accept',
            'Accept-Language',
            'Accept-Encoding',
            'Origin',
            'Referer',
            'User-Agent',
            'Cache-Control',
            'Pragma'
        ].join(', ');

        res.setHeader('Access-Control-Allow-Headers', allowedHeaders);

        // ============================================
        // 7. EXPOSED HEADERS
        // ============================================
        const exposedHeaders = [
            'X-Request-ID',
            'X-Response-Time',
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'X-Total-Count',
            'X-Page-Count',
            'Content-Length',
            'Content-Type'
        ].join(', ');

        res.setHeader('Access-Control-Expose-Headers', exposedHeaders);

        // ============================================
        // 8. MAX AGE (Cache preflight)
        // ============================================
        res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours

        // ============================================
        // 9. HANDLE PREFLIGHT (OPTIONS)
        // ============================================
        if (req.method === 'OPTIONS') {
            // Respond to preflight immediately
            return res.status(204).end();
        }

        // ============================================
        // 10. VARY HEADER
        // ============================================
        res.setHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');

        // ============================================
        // 11. SECURITY: Block requests from blocked origins
        // ============================================
        if (!isAllowed && requestOrigin) {
            console.warn(`🚫 CORS Blocked: ${requestOrigin} → ${req.method} ${req.path}`);
            
            return res.status(403).json({
                success: false,
                error: 'Origin not allowed',
                code: 'CORS_BLOCKED',
                message: 'Cross-origin requests from this origin are not permitted.'
            });
        }

        // ============================================
        // 12. LOG CORS REQUEST
        // ============================================
        if (requestOrigin) {
            console.log(`🌐 CORS: ${requestOrigin} → ${req.method} ${req.path} [${isAllowed ? 'ALLOWED' : 'BLOCKED'}]`);
        }

        // ============================================
        // 13. PROCEED
        // ============================================
        next();

    } catch (error) {
        console.error('CORS Middleware Error:', error);
        
        return res.status(500).json({
            success: false,
            error: 'CORS processing error',
            code: 'CORS_ERROR'
        });
    }
}

// ============================================
// ALLOWED ORIGINS CONFIGURATION
// ============================================
function getAllowedOrigins() {
    const env = process.env.NODE_ENV || 'production';

    // Production origins
    const productionOrigins = [
        'https://secure-website.vercel.app',
        'https://www.securesite.com',
        'https://securesite.com',
        'https://admin.securesite.com',
        'https://api.securesite.com'
    ];

    // Development origins
    const developmentOrigins = [
        'http://localhost:3000',
        'http://localhost:5000',
        'http://localhost:8000',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:5000',
        'http://127.0.0.1:8000'
    ];

    if (env === 'development') {
        return [...developmentOrigins, ...productionOrigins];
    }

    return productionOrigins;
}

// ============================================
// ORIGIN VALIDATION
// ============================================
function isOriginAllowed(origin, allowedOrigins) {
    // No origin = same-origin request (always allowed)
    if (!origin) return true;

    // Check exact match
    if (allowedOrigins.includes(origin)) return true;

    // Check wildcard
    if (allowedOrigins.includes('*')) return true;

    // Check pattern matching
    return allowedOrigins.some(pattern => {
        // Convert glob pattern to regex
        if (pattern.includes('*')) {
            const regex = new RegExp(
                '^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$'
            );
            return regex.test(origin);
        }
        return false;
    });
}

// ============================================
// CORS FOR SPECIFIC ROUTES
// ============================================
export function corsForPublic(req, res, next) {
    // Allow all origins for public endpoints
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '3600');

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    next();
}

export function corsForAuthenticated(req, res, next) {
    // Allow only authenticated origins
    const allowedOrigins = getAllowedOrigins();
    const origin = req.headers.origin;

    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    next();
}

export function corsForAdmin(req, res, next) {
    // Strict CORS for admin routes
    const adminOrigins = [
        'https://secure-website.vercel.app',
        'https://admin.securesite.com'
    ];

    const origin = req.headers.origin;

    if (origin && adminOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token, X-Admin-Key');
    res.setHeader('Access-Control-Max-Age', '3600');

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    // Block non-admin origins
    if (origin && !adminOrigins.includes(origin)) {
        return res.status(403).json({
            success: false,
            error: 'Admin access only',
            code: 'CORS_ADMIN_ONLY'
        });
    }

    next();
}
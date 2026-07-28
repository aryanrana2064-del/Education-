// ============================================
// SECURE WEBSITE — Token Verification API v2.0
// JWT / Session Token Validation Endpoint
// ============================================

export default async function handler(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Handle preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Only accept GET and POST
    if (!['GET', 'POST'].includes(req.method)) {
        return res.status(405).json({
            success: false,
            error: 'Method not allowed',
            code: 405
        });
    }

    try {
        // Get token from header or body
        const authHeader = req.headers.authorization;
        const token = authHeader 
            ? authHeader.replace('Bearer ', '') 
            : (req.body?.token || req.query?.token);

        if (!token) {
            return res.status(400).json({
                success: false,
                valid: false,
                error: 'No token provided',
                code: 400
            });
        }

        // Verify token
        const verification = verifyToken(token);

        if (!verification.valid) {
            return res.status(401).json({
                success: false,
                valid: false,
                error: verification.error || 'Invalid token',
                code: 401
            });
        }

        // Token is valid
        return res.status(200).json({
            success: true,
            valid: true,
            data: {
                userId: verification.userId,
                email: verification.email,
                role: verification.role,
                issuedAt: verification.issuedAt,
                expiresAt: verification.expiresAt,
                remainingTime: verification.remainingTime
            }
        });

    } catch (error) {
        console.error('Token Verification Error:', error);
        
        return res.status(500).json({
            success: false,
            valid: false,
            error: 'Internal server error',
            code: 500
        });
    }
}

// ============================================
// TOKEN VERIFICATION LOGIC
// ============================================
function verifyToken(token) {
    // Token format: acc_xxxxxxxx_xxxxxxx or ref_xxxxxxxx_xxxxxxx
    const parts = token.split('_');
    
    if (parts.length < 3) {
        return { valid: false, error: 'Invalid token format' };
    }

    const prefix = parts[0];
    const timestamp = parseInt(parts[1], 36);
    const random = parts.slice(2).join('_');

    if (!prefix || !timestamp || !random) {
        return { valid: false, error: 'Malformed token' };
    }

    // Check token type
    if (!['acc', 'ref'].includes(prefix)) {
        return { valid: false, error: 'Unknown token type' };
    }

    // Check expiry (access tokens: 1 hour, refresh tokens: 7 days)
    const now = Date.now();
    const accessExpiry = 3600000;  // 1 hour
    const refreshExpiry = 604800000; // 7 days
    
    const expiryTime = prefix === 'acc' 
        ? timestamp + accessExpiry 
        : timestamp + refreshExpiry;

    if (now > expiryTime) {
        return { 
            valid: false, 
            error: 'Token expired',
            expiredAt: new Date(expiryTime).toISOString()
        };
    }

    // Token is valid (in production, verify signature against database)
    return {
        valid: true,
        userId: 'usr_' + Math.abs(hashCode(token)).toString(36),
        email: 'user@securesite.com',
        role: prefix === 'acc' ? 'user' : 'user',
        issuedAt: new Date(timestamp).toISOString(),
        expiresAt: new Date(expiryTime).toISOString(),
        remainingTime: Math.max(0, expiryTime - now),
        tokenType: prefix === 'acc' ? 'access' : 'refresh'
    };
}

// Simple string hash for demo (use proper JWT in production)
function hashCode(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0;
    }
    return Math.abs(hash);
}
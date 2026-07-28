// ============================================
// SECURE WEBSITE — Auth Middleware v2.0
// Request Authentication & Authorization
// ============================================

export default async function authMiddleware(req, res, next) {
    try {
        // ============================================
        // 1. EXTRACT TOKEN
        // ============================================
        const authHeader = req.headers.authorization;
        const token = authHeader 
            ? authHeader.replace('Bearer ', '') 
            : (req.cookies?.auth_token || req.query?.token);

        // ============================================
        // 2. CHECK IF TOKEN EXISTS
        // ============================================
        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required',
                code: 'AUTH_REQUIRED',
                message: 'Please provide a valid authentication token.'
            });
        }

        // ============================================
        // 3. VERIFY TOKEN
        // ============================================
        const verification = verifyAuthToken(token);

        if (!verification.valid) {
            // Clear invalid cookie
            res.setHeader('Set-Cookie', 'auth_token=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/');

            return res.status(401).json({
                success: false,
                error: 'Invalid or expired token',
                code: 'TOKEN_INVALID',
                message: verification.error || 'Token validation failed.'
            });
        }

        // ============================================
        // 4. CHECK USER EXISTS (Optional - DB check)
        // ============================================
        const user = await getUserFromToken(verification);
        
        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND',
                message: 'The user associated with this token no longer exists.'
            });
        }

        // ============================================
        // 5. CHECK USER STATUS
        // ============================================
        if (user.status === 'blocked' || user.status === 'suspended') {
            return res.status(403).json({
                success: false,
                error: 'Account ' + user.status,
                code: 'ACCOUNT_' + user.status.toUpperCase(),
                message: `Your account has been ${user.status}. Please contact support.`
            });
        }

        // ============================================
        // 6. CHECK EMAIL VERIFIED (Optional)
        // ============================================
        if (!user.emailVerified && req.path !== '/api/verify-email') {
            return res.status(403).json({
                success: false,
                error: 'Email not verified',
                code: 'EMAIL_NOT_VERIFIED',
                message: 'Please verify your email address before accessing this resource.'
            });
        }

        // ============================================
        // 7. ATTACH USER TO REQUEST
        // ============================================
        req.user = {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            permissions: user.permissions || [],
            tokenExpiry: verification.expiresAt
        };

        // ============================================
        // 8. REFRESH TOKEN IF NEEDED
        // ============================================
        const timeUntilExpiry = verification.expiresAt - Date.now();
        const refreshThreshold = 300000; // 5 minutes

        if (timeUntilExpiry < refreshThreshold && timeUntilExpiry > 0) {
            const newToken = generateToken('access');
            
            res.setHeader('Set-Cookie', 
                `auth_token=${newToken}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600; Path=/`
            );
            
            res.setHeader('X-Token-Refreshed', 'true');
            res.setHeader('X-New-Token', newToken);
        }

        // ============================================
        // 9. LOG ACCESS
        // ============================================
        console.log(`🔐 Auth: ${user.email} → ${req.method} ${req.path}`);

        // ============================================
        // 10. PROCEED TO NEXT MIDDLEWARE/ROUTE
        // ============================================
        next();

    } catch (error) {
        console.error('Auth Middleware Error:', error);
        
        return res.status(500).json({
            success: false,
            error: 'Authentication error',
            code: 'AUTH_ERROR',
            message: 'An error occurred during authentication.'
        });
    }
}

// ============================================
// ROLE-BASED ACCESS CONTROL
// ============================================
export function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                error: 'Insufficient permissions',
                code: 'FORBIDDEN',
                message: `This resource requires one of these roles: ${allowedRoles.join(', ')}`
            });
        }

        next();
    };
}

export function requirePermission(...requiredPermissions) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        // Admin has all permissions
        if (req.user.role === 'admin') {
            return next();
        }

        const hasPermission = requiredPermissions.some(p => 
            req.user.permissions.includes(p)
        );

        if (!hasPermission) {
            return res.status(403).json({
                success: false,
                error: 'Insufficient permissions',
                code: 'FORBIDDEN',
                message: `Missing required permission: ${requiredPermissions.join(', ')}`
            });
        }

        next();
    };
}

// ============================================
// HELPER FUNCTIONS
// ============================================
function verifyAuthToken(token) {
    const parts = token.split('_');
    
    if (parts.length < 3) {
        return { valid: false, error: 'Invalid token format' };
    }

    const prefix = parts[0];
    const timestamp = parseInt(parts[1], 36);

    if (!['acc', 'ref'].includes(prefix)) {
        return { valid: false, error: 'Unknown token type' };
    }

    const accessExpiry = 3600000;
    const refreshExpiry = 604800000;
    const expiryTime = prefix === 'acc' 
        ? timestamp + accessExpiry 
        : timestamp + refreshExpiry;

    if (Date.now() > expiryTime) {
        return { valid: false, error: 'Token expired' };
    }

    return {
        valid: true,
        tokenType: prefix,
        issuedAt: timestamp,
        expiresAt: expiryTime
    };
}

async function getUserFromToken(verification) {
    // Simulate database lookup
    return {
        id: 'usr_' + Math.random().toString(36).substring(2, 9),
        email: 'user@securesite.com',
        name: 'Authenticated User',
        role: verification.tokenType === 'acc' ? 'user' : 'user',
        status: 'active',
        emailVerified: true,
        permissions: ['read', 'write']
    };
}

function generateToken(type = 'access') {
    const prefix = type === 'access' ? 'acc' : 'ref';
    return prefix + '_' + Date.now().toString(36) + '_' + 
           Math.random().toString(36).substring(2, 15);
}

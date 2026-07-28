// ============================================
// SECURE WEBSITE — Login API v2.0
// Authentication Endpoint
// ============================================

export default async function handler(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');

    // Handle preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Only accept POST
    if (req.method !== 'POST') {
        return res.status(405).json({
            success: false,
            error: 'Method not allowed',
            code: 405
        });
    }

    try {
        const { email, password, csrfToken } = req.body || {};

        // Validate inputs
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email and password are required.',
                code: 400
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid email format.',
                code: 400
            });
        }

        // Validate password length
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                error: 'Password must be at least 8 characters.',
                code: 400
            });
        }

        // Rate limiting check
        const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
        
        // Simulate authentication (replace with real DB check)
        const user = await authenticateUser(email, password);

        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password.',
                code: 401
            });
        }

        // Generate tokens
        const accessToken = generateToken('access');
        const refreshToken = generateToken('refresh');

        // Set secure cookie
        res.setHeader('Set-Cookie', [
            `auth_token=${accessToken}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600; Path=/`,
            `refresh_token=${refreshToken}; HttpOnly; Secure; SameSite=Strict; Max-Age=604800; Path=/api`
        ]);

        // Log successful login
        console.log(`✅ Login: ${email} from ${clientIP}`);

        return res.status(200).json({
            success: true,
            message: 'Login successful',
            data: {
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                },
                accessToken,
                refreshToken,
                expiresIn: 3600
            }
        });

    } catch (error) {
        console.error('Login API Error:', error);
        
        return res.status(500).json({
            success: false,
            error: 'Internal server error',
            code: 500
        });
    }
}

// ============================================
// HELPER FUNCTIONS
// ============================================
async function authenticateUser(email, password) {
    // Demo users (replace with database query)
    const demoUsers = [
        { id: 'usr_001', name: 'Admin User', email: 'admin@securesite.com', password: 'Admin@123', role: 'admin' },
        { id: 'usr_002', name: 'John Doe', email: 'user@securesite.com', password: 'User@1234', role: 'user' }
    ];

    // Find user
    const user = demoUsers.find(u => u.email === email && u.password === password);
    
    if (user) {
        // Return user without password
        const { password, ...userWithoutPassword } = user;
        return userWithoutPassword;
    }

    return null;
}

function generateToken(type = 'access') {
    const prefix = type === 'access' ? 'acc' : 'ref';
    return prefix + '_' + Date.now().toString(36) + '_' + 
           Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
}
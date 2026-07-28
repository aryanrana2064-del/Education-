// ============================================
// SECURE WEBSITE — Logout API v2.0
// Session Termination Endpoint
// ============================================

export default async function handler(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

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
        const authHeader = req.headers.authorization;
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;

        // Clear auth cookies
        res.setHeader('Set-Cookie', [
            'auth_token=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/',
            'refresh_token=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/api'
        ]);

        // Log logout
        console.log(`👋 Logout: Token ${token ? token.substring(0, 10) + '...' : 'unknown'}`);

        return res.status(200).json({
            success: true,
            message: 'Logged out successfully'
        });

    } catch (error) {
        console.error('Logout API Error:', error);
        
        return res.status(500).json({
            success: false,
            error: 'Internal server error',
            code: 500
        });
    }
}
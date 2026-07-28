// ============================================
// SECURE WEBSITE — Security Headers Module v2.0
// HTTP Security Headers & Content Security Policy
// ============================================

class SecurityHeaders {
    constructor() {
        this.headers = {};
        this.metaTags = [];
        this.initialized = false;
        this.reportOnly = false;
        this.cspReportUri = '/api/csp-report';
        
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    init() {
        this.setupDefaultHeaders();
        this.applyMetaTags();
        this.initialized = true;
        console.log('📋 Security Headers Module Loaded');
    }

    // ============================================
    // DEFAULT SECURITY HEADERS
    // ============================================
    setupDefaultHeaders() {
        this.headers = {
            // Content Security Policy
            'Content-Security-Policy': this.buildCSP(),
            
            // Prevent MIME type sniffing
            'X-Content-Type-Options': 'nosniff',
            
            // Prevent clickjacking
            'X-Frame-Options': 'DENY',
            
            // Enable browser XSS filter
            'X-XSS-Protection': '1; mode=block',
            
            // Referrer policy
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            
            // HTTP Strict Transport Security
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            
            // Permissions policy
            'Permissions-Policy': [
                'camera=()',
                'microphone=()',
                'geolocation=()',
                'interest-cohort=()',
                'payment=()',
                'usb=()',
                'vr=()',
                'accelerometer=()',
                'autoplay=()',
                'clipboard-read=()',
                'clipboard-write=(self)',
                'display-capture=()',
                'gyroscope=()',
                'magnetometer=()'
            ].join(', '),
            
            // Cross-Origin policies
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
            
            // Cache control
            'Cache-Control': 'no-store, max-age=0, must-revalidate',
            
            // DNS prefetch control
            'X-DNS-Prefetch-Control': 'off',
            
            // Download policy
            'X-Download-Options': 'noopen',
            
            // Hide server information
            'Server': 'CloudShield',
            
            // Clear site data (on logout)
            'Clear-Site-Data': '"cache","cookies","storage"'
        };
    }

    // ============================================
    // CONTENT SECURITY POLICY (CSP)
    // ============================================
    buildCSP() {
        const csp = {
            'default-src': ["'self'"],
            'script-src': [
                "'self'",
                "'unsafe-inline'",
                "'unsafe-eval'",
                'https://cdnjs.cloudflare.com',
                'https://www.gstatic.com',
                'https://www.google.com',
                'https://www.gstatic.com/firebasejs'
            ],
            'style-src': [
                "'self'",
                "'unsafe-inline'",
                'https://fonts.googleapis.com',
                'https://cdnjs.cloudflare.com'
            ],
            'font-src': [
                "'self'",
                'https://fonts.gstatic.com',
                'https://cdnjs.cloudflare.com',
                'data:'
            ],
            'img-src': [
                "'self'",
                'data:',
                'https:',
                'blob:'
            ],
            'media-src': [
                "'self'",
                'https:'
            ],
            'connect-src': [
                "'self'",
                'https:',
                'wss:'
            ],
            'frame-src': [
                "'none'"
            ],
            'frame-ancestors': [
                "'none'"
            ],
            'object-src': [
                "'none'"
            ],
            'base-uri': [
                "'self'"
            ],
            'form-action': [
                "'self'"
            ],
            'manifest-src': [
                "'self'"
            ],
            'worker-src': [
                "'self'"
            ],
            'upgrade-insecure-requests': []
        };

        // Build CSP string
        const directives = [];
        for (const [directive, sources] of Object.entries(csp)) {
            if (sources.length > 0) {
                directives.push(`${directive} ${sources.join(' ')}`);
            } else {
                directives.push(directive);
            }
        }

        // Add report URI if set
        if (this.cspReportUri) {
            directives.push(`report-uri ${this.cspReportUri}`);
        }

        return directives.join('; ');
    }

    // ============================================
    // APPLY META TAGS TO DOM
    // ============================================
    applyMetaTags() {
        // Remove existing security meta tags
        document.querySelectorAll('meta[http-equiv]').forEach(el => {
            const httpEquiv = el.getAttribute('http-equiv').toLowerCase();
            if (['content-security-policy', 'x-content-type-options', 
                 'x-frame-options', 'x-xss-protection', 'referrer-policy',
                 'strict-transport-security'].includes(httpEquiv)) {
                el.remove();
            }
        });

        // Apply new meta tags
        const metaTags = [
            { httpEquiv: 'Content-Security-Policy', content: this.headers['Content-Security-Policy'] },
            { httpEquiv: 'X-Content-Type-Options', content: this.headers['X-Content-Type-Options'] },
            { httpEquiv: 'X-Frame-Options', content: this.headers['X-Frame-Options'] },
            { httpEquiv: 'X-XSS-Protection', content: this.headers['X-XSS-Protection'] },
            { httpEquiv: 'Referrer-Policy', content: this.headers['Referrer-Policy'] }
        ];

        metaTags.forEach(tag => {
            if (!document.querySelector(`meta[http-equiv="${tag.httpEquiv}"]`)) {
                const meta = document.createElement('meta');
                meta.httpEquiv = tag.httpEquiv;
                meta.content = tag.content;
                document.head.insertBefore(meta, document.head.firstChild);
            }
        });

        this.metaTags = metaTags;
    }

    // ============================================
    // CSP REPORT HANDLING
    // ============================================
    setupCSPReporting() {
        document.addEventListener('securitypolicyviolation', (e) => {
            const report = {
                'csp-report': {
                    'document-uri': e.documentURI,
                    'referrer': e.referrer,
                    'violated-directive': e.violatedDirective,
                    'effective-directive': e.effectiveDirective,
                    'original-policy': e.originalPolicy,
                    'blocked-uri': e.blockedURI,
                    'source-file': e.sourceFile,
                    'line-number': e.lineNumber,
                    'column-number': e.columnNumber,
                    'status-code': e.statusCode
                }
            };

            console.warn('🚨 CSP Violation:', report['csp-report']);
            
            // Log to security system
            if (window.Logger) {
                Logger.log('csp_violation', 'system', report['csp-report']);
            }

            // Send to report URI (if configured)
            if (this.cspReportUri) {
                this.sendCSPReport(report);
            }
        });
    }

    async sendCSPReport(report) {
        try {
            await fetch(this.cspReportUri, {
                method: 'POST',
                headers: { 'Content-Type': 'application/csp-report' },
                body: JSON.stringify(report)
            });
        } catch (error) {
            console.error('Failed to send CSP report:', error);
        }
    }

    // ============================================
    // HEADER MANAGEMENT
    // ============================================
    setHeader(name, value) {
        this.headers[name] = value;
        
        // Update meta tag if applicable
        if (['Content-Security-Policy', 'X-Content-Type-Options', 
             'X-Frame-Options', 'X-XSS-Protection', 'Referrer-Policy'].includes(name)) {
            const meta = document.querySelector(`meta[http-equiv="${name}"]`);
            if (meta) {
                meta.content = value;
            }
        }
    }

    getHeader(name) {
        return this.headers[name] || null;
    }

    getAllHeaders() {
        return { ...this.headers };
    }

    // ============================================
    // CSP MANAGEMENT
    // ============================================
    updateCSP(directive, sources) {
        const cspParts = this.headers['Content-Security-Policy'].split(';').map(d => d.trim());
        const existingIndex = cspParts.findIndex(p => p.startsWith(directive));
        
        const newDirective = sources.length > 0 ? 
            `${directive} ${sources.join(' ')}` : directive;

        if (existingIndex >= 0) {
            cspParts[existingIndex] = newDirective;
        } else {
            cspParts.push(newDirective);
        }

        const newCSP = cspParts.join('; ');
        this.setHeader('Content-Security-Policy', newCSP);
    }

    addToCSP(directive, source) {
        const cspParts = this.headers['Content-Security-Policy'].split(';').map(d => d.trim());
        const existingIndex = cspParts.findIndex(p => p.startsWith(directive));
        
        if (existingIndex >= 0) {
            const parts = cspParts[existingIndex].split(' ');
            if (!parts.includes(source)) {
                parts.push(source);
                cspParts[existingIndex] = parts.join(' ');
            }
        } else {
            cspParts.push(`${directive} ${source}`);
        }

        const newCSP = cspParts.join('; ');
        this.setHeader('Content-Security-Policy', newCSP);
    }

    removeFromCSP(directive, source) {
        const cspParts = this.headers['Content-Security-Policy'].split(';').map(d => d.trim());
        const existingIndex = cspParts.findIndex(p => p.startsWith(directive));
        
        if (existingIndex >= 0) {
            const parts = cspParts[existingIndex].split(' ');
            const filtered = parts.filter(p => p !== source);
            if (filtered.length <= 1) {
                cspParts.splice(existingIndex, 1);
            } else {
                cspParts[existingIndex] = filtered.join(' ');
            }
        }

        const newCSP = cspParts.join('; ');
        this.setHeader('Content-Security-Policy', newCSP);
    }

    // ============================================
    // SECURITY HEADER CHECKS
    // ============================================
    checkSecurityHeaders() {
        const results = [];
        const requiredHeaders = [
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Strict-Transport-Security',
            'Permissions-Policy'
        ];

        requiredHeaders.forEach(header => {
            results.push({
                header,
                present: !!this.headers[header],
                value: this.headers[header] || 'MISSING',
                status: this.headers[header] ? '✅' : '❌'
            });
        });

        return results;
    }

    getSecurityGrade() {
        const checks = this.checkSecurityHeaders();
        const passed = checks.filter(c => c.present).length;
        const total = checks.length;
        const percentage = Math.round((passed / total) * 100);

        if (percentage === 100) return { grade: 'A+', percentage };
        if (percentage >= 85) return { grade: 'A', percentage };
        if (percentage >= 70) return { grade: 'B', percentage };
        if (percentage >= 50) return { grade: 'C', percentage };
        return { grade: 'F', percentage };
    }

    // ============================================
    // REPORT-ONLY MODE
    // ============================================
    enableReportOnly() {
        this.reportOnly = true;
        const csp = this.headers['Content-Security-Policy'];
        this.setHeader('Content-Security-Policy-Report-Only', csp);
        console.log('📋 CSP Report-Only mode enabled');
    }

    disableReportOnly() {
        this.reportOnly = false;
        console.log('📋 CSP Report-Only mode disabled');
    }

    // ============================================
    // HEADERS FOR SPECIFIC PAGES
    // ============================================
    applyLoginPageHeaders() {
        this.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        this.setHeader('Pragma', 'no-cache');
        this.addToCSP('form-action', "'self'");
        this.addToCSP('frame-ancestors', "'none'");
    }

    applyDashboardHeaders() {
        this.setHeader('Cache-Control', 'no-store, max-age=0');
        this.addToCSP('script-src', "'unsafe-inline'");
    }

    applyAdminHeaders() {
        this.setHeader('Cache-Control', 'no-store, max-age=0');
        this.addToCSP('script-src', "'unsafe-inline'");
        this.addToCSP('connect-src', 'https://api.example.com');
    }

    // ============================================
    // CLEANUP
    // ============================================
    destroy() {
        this.initialized = false;
        this.headers = {};
        this.metaTags = [];
        console.log('Security Headers module destroyed');
    }
}

// ============================================
// INITIALIZE GLOBAL HEADERS INSTANCE
// ============================================
window.SecurityHeaders = new SecurityHeaders();

// Setup CSP violation reporting
window.SecurityHeaders.setupCSPReporting();
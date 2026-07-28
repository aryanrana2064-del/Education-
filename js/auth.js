// ============================================
// SECURE WEBSITE — Authentication Logic v2.0
// Login, Registration, Password Management
// ============================================

class Auth {
    constructor() {
        this.apiBase = '/api';
        this.tokenKey = 'secure_auth_token';
        this.userKey = 'secure_user_data';
        this.rememberKey = 'secure_remember';
        this.sessionTimeout = 3600000; // 1 hour
        this.initialized = false;
        
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    init() {
        this.setupForms();
        this.checkResetToken();
        this.initialized = true;
        console.log('🔐 Auth Module Loaded');
    }

    // ============================================
    // FORM SETUP
    // ============================================
    setupForms() {
        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Registration form
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        }

        // Password reset form
        const resetForm = document.getElementById('resetForm');
        if (resetForm) {
            resetForm.addEventListener('submit', (e) => this.handlePasswordReset(e));
        }
    }

    // ============================================
    // LOGIN
    // ============================================
    async handleLogin(event) {
        event.preventDefault();
        
        const emailInput = document.getElementById('loginEmail');
        const passwordInput = document.getElementById('loginPassword');
        const rememberInput = document.getElementById('rememberMe');
        const errorDiv = document.getElementById('loginError');
        const submitBtn = document.getElementById('loginSubmitBtn');

        if (!emailInput || !passwordInput) return;

        const email = emailInput.value.trim();
        const password = passwordInput.value;
        const remember = rememberInput?.checked || false;

        // Clear previous errors
        this.clearErrors();

        // Validate email
        if (!email) {
            this.showFieldError('emailError', 'Email is required.');
            return;
        }
        if (window.Validator && !window.Validator.validateEmail(email)) {
            this.showFieldError('emailError', 'Please enter a valid email.');
            return;
        }

        // Validate password
        if (!password) {
            this.showFieldError('passwordError', 'Password is required.');
            return;
        }
        if (password.length < 8) {
            this.showFieldError('passwordError', 'Password must be at least 8 characters.');
            return;
        }

        // Check rate limit
        if (window.RateLimiter) {
            const rateCheck = window.RateLimiter.checkLogin('login_' + email);
            if (!rateCheck.allowed) {
                this.showError('Too many attempts. Please wait ' + rateCheck.retryAfter + ' seconds.');
                return;
            }
        }

        // Show loading
        this.setLoading(true, submitBtn);

        try {
            // Simulate API call (replace with real API)
            const result = await this.authenticateUser(email, password);

            if (result.success) {
                // Save auth data
                this.saveAuthData(result.user, result.token, remember);
                
                // Log success
                if (window.Logger) {
                    Logger.logLogin(email, true);
                }

                // Show success
                this.showNotification('Login successful! Redirecting...', 'success');

                // Redirect
                const redirectUrl = this.getRedirectUrl(result.user.role);
                setTimeout(() => {
                    window.location.href = redirectUrl;
                }, 800);
            } else {
                this.showError(result.error || 'Invalid credentials.');
                
                if (window.Logger) {
                    Logger.logLogin(email, false, { error: result.error });
                }
            }
        } catch (error) {
            this.showError('An error occurred. Please try again.');
            console.error('Login error:', error);
        } finally {
            this.setLoading(false, submitBtn);
        }
    }

    // ============================================
    // REGISTRATION
    // ============================================
    async handleRegister(event) {
        event.preventDefault();

        const nameInput = document.getElementById('registerName');
        const emailInput = document.getElementById('registerEmail');
        const passwordInput = document.getElementById('registerPassword');
        const confirmInput = document.getElementById('registerConfirm');
        const submitBtn = document.getElementById('registerSubmitBtn');

        if (!nameInput || !emailInput || !passwordInput || !confirmInput) return;

        const name = nameInput.value.trim();
        const email = emailInput.value.trim();
        const password = passwordInput.value;
        const confirm = confirmInput.value;

        this.clearErrors();

        // Validate name
        if (!name || name.length < 2) {
            this.showFieldError('nameError', 'Name must be at least 2 characters.');
            return;
        }

        // Validate email
        if (!window.Validator?.validateEmail(email)) {
            this.showFieldError('emailError', 'Please enter a valid email.');
            return;
        }

        // Validate password
        if (!window.Validator?.validatePassword(password)) {
            this.showFieldError('passwordError', 'Password must be 8+ chars with uppercase, lowercase, number & symbol.');
            return;
        }

        // Confirm password
        if (password !== confirm) {
            this.showFieldError('confirmError', 'Passwords do not match.');
            return;
        }

        this.setLoading(true, submitBtn);

        try {
            const result = await this.registerUser(name, email, password);

            if (result.success) {
                this.showNotification('Registration successful! Please login.', 'success');
                setTimeout(() => {
                    window.location.href = '/login';
                }, 1500);
            } else {
                this.showError(result.error || 'Registration failed.');
            }
        } catch (error) {
            this.showError('An error occurred. Please try again.');
        } finally {
            this.setLoading(false, submitBtn);
        }
    }

    // ============================================
    // PASSWORD RESET
    // ============================================
    async handlePasswordReset(event) {
        event.preventDefault();

        const emailInput = document.getElementById('resetEmail');
        const submitBtn = document.getElementById('resetSubmitBtn');

        if (!emailInput) return;

        const email = emailInput.value.trim();

        if (!window.Validator?.validateEmail(email)) {
            this.showError('Please enter a valid email.');
            return;
        }

        this.setLoading(true, submitBtn);

        try {
            const result = await this.requestPasswordReset(email);

            if (result.success) {
                this.showNotification('Password reset link sent to your email!', 'success');
            } else {
                this.showError(result.error || 'Failed to send reset link.');
            }
        } catch (error) {
            this.showError('An error occurred. Please try again.');
        } finally {
            this.setLoading(false, submitBtn);
        }
    }

    // ============================================
    // API CALLS (Simulated — Replace with real API)
    // ============================================
    async authenticateUser(email, password) {
        // Simulate network delay
        await this.delay(800 + Math.random() * 400);

        // Demo accounts
        const demoAccounts = {
            'admin@securesite.com': {
                password: 'Admin@123',
                name: 'Admin User',
                role: 'admin',
                id: 'usr_admin_001'
            },
            'user@securesite.com': {
                password: 'User@1234',
                name: 'John Doe',
                role: 'user',
                id: 'usr_user_001'
            }
        };

        // Hash password (demo only)
        let hashedPassword = password;
        if (window.Encryption) {
            hashedPassword = await window.Encryption.hash(password);
        }

        // Check demo accounts
        if (demoAccounts[email] && demoAccounts[email].password === password) {
            const user = demoAccounts[email];
            return {
                success: true,
                user: { id: user.id, name: user.name, email, role: user.role },
                token: this.generateToken()
            };
        }

        // Accept valid-looking credentials for demo
        if (window.Validator?.validateEmail(email) && password.length >= 8) {
            return {
                success: true,
                user: {
                    id: 'usr_' + Date.now().toString(36),
                    name: email.split('@')[0],
                    email,
                    role: email.includes('admin') ? 'admin' : 'user'
                },
                token: this.generateToken()
            };
        }

        return { success: false, error: 'Invalid email or password.' };
    }

    async registerUser(name, email, password) {
        await this.delay(1000);
        return { success: true };
    }

    async requestPasswordReset(email) {
        await this.delay(800);
        return { success: true };
    }

    async resetPassword(token, newPassword) {
        await this.delay(800);
        return { success: true };
    }

    // ============================================
    // AUTH DATA MANAGEMENT
    // ============================================
    saveAuthData(user, token, remember) {
        // Save token
        localStorage.setItem(this.tokenKey, token);
        
        // Save user data
        localStorage.setItem(this.userKey, JSON.stringify(user));
        
        // Remember me
        if (remember) {
            localStorage.setItem(this.rememberKey, 'true');
        }

        // Set session expiry
        const session = {
            token,
            expiresAt: Date.now() + this.sessionTimeout
        };
        sessionStorage.setItem('secure_session', JSON.stringify(session));
    }

    clearAuthData() {
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.userKey);
        localStorage.removeItem(this.rememberKey);
        sessionStorage.removeItem('secure_session');
    }

    getToken() {
        return localStorage.getItem(this.tokenKey);
    }

    getUser() {
        try {
            return JSON.parse(localStorage.getItem(this.userKey));
        } catch {
            return null;
        }
    }

    isLoggedIn() {
        const token = this.getToken();
        const session = JSON.parse(sessionStorage.getItem('secure_session') || '{}');
        return !!token && (!session.expiresAt || Date.now() < session.expiresAt);
    }

    // ============================================
    // LOGOUT
    // ============================================
    logout() {
        if (window.Logger) {
            Logger.log('logout', this.getUser()?.email || 'user');
        }
        
        this.clearAuthData();
        
        if (window.AuthGuard) {
            window.AuthGuard.logout();
        }
        
        window.location.href = '/login';
    }

    // ============================================
    // UTILITIES
    // ============================================
    generateToken() {
        return 'tok_' + Date.now().toString(36) + '_' + 
               Math.random().toString(36).substr(2, 20);
    }

    getRedirectUrl(role) {
        if (role === 'admin') return '/admin';
        return '/dashboard';
    }

    checkResetToken() {
        const params = new URLSearchParams(window.location.search);
        const resetToken = params.get('reset_token');
        
        if (resetToken && window.location.pathname.includes('reset-password')) {
            document.getElementById('resetToken').value = resetToken;
        }
    }

    setLoading(isLoading, button) {
        if (!button) return;
        
        const loader = button.querySelector('.btn-loader');
        const text = button.querySelector('.btn-text');
        
        if (isLoading) {
            button.disabled = true;
            button.style.opacity = '0.7';
            if (loader) loader.style.display = 'inline-block';
        } else {
            button.disabled = false;
            button.style.opacity = '1';
            if (loader) loader.style.display = 'none';
        }
    }

    showError(message) {
        const errorDiv = document.getElementById('loginError') || document.getElementById('authError');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.style.display = 'flex';
        }
    }

    showFieldError(elementId, message) {
        const el = document.getElementById(elementId);
        if (el) {
            el.textContent = message;
            el.style.display = 'block';
        }
    }

    clearErrors() {
        document.querySelectorAll('.field-error').forEach(el => {
            el.textContent = '';
            el.style.display = 'none';
        });
        const errorDiv = document.getElementById('loginError') || document.getElementById('authError');
        if (errorDiv) errorDiv.style.display = 'none';
    }

    showNotification(message, type = 'info') {
        if (window.App) {
            window.App.showToast(message, type);
        } else {
            alert(message);
        }
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // ============================================
    // CLEANUP
    // ============================================
    destroy() {
        this.initialized = false;
        console.log('Auth module destroyed');
    }
}

// ============================================
// INITIALIZE GLOBAL AUTH INSTANCE
// ============================================
window.Auth = new Auth();
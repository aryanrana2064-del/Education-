// ============================================
// SECURE WEBSITE — Main Application v2.0
// Core App Logic, Navigation & UI Controller
// ============================================

class App {
    constructor() {
        this.version = '2.0.0';
        this.initialized = false;
        this.currentPage = this.getCurrentPage();
        this.startTime = Date.now();
        
        this.config = {
            animations: true,
            smoothScroll: true,
            lazyLoad: true,
            debug: false,
            toastDuration: 4000,
            sessionCheckInterval: 60000
        };
        
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    init() {
        if (this.initialized) return;
        
        this.log('App v' + this.version + ' initializing...');
        
        this.setupNavigation();
        this.setupSmoothScroll();
        this.setupScrollAnimations();
        this.setupHeaderScroll();
        this.setupKeyboardShortcuts();
        this.setupExternalLinks();
        this.checkAuthState();
        
        this.initialized = true;
        this.log('✅ App initialized successfully');
        
        // Log page view
        if (window.Logger) {
            Logger.logPageView(this.currentPage);
        }
    }

    // ============================================
    // NAVIGATION SETUP
    // ============================================
    setupNavigation() {
        // Mobile menu toggle
        const menuToggle = document.getElementById('menuToggle');
        const nav = document.getElementById('nav');
        
        if (menuToggle && nav) {
            menuToggle.addEventListener('click', () => {
                const isOpen = nav.classList.toggle('open');
                menuToggle.classList.toggle('active');
                menuToggle.setAttribute('aria-expanded', isOpen);
                document.body.style.overflow = isOpen ? 'hidden' : '';
            });
        }

        // Close menu on link click
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                if (nav) nav.classList.remove('open');
                if (menuToggle) menuToggle.classList.remove('active');
                document.body.style.overflow = '';
            });
        });

        // Close menu on Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && nav?.classList.contains('open')) {
                nav.classList.remove('open');
                if (menuToggle) menuToggle.classList.remove('active');
                document.body.style.overflow = '';
            }
        });

        // Close menu on outside click
        document.addEventListener('click', (e) => {
            if (nav?.classList.contains('open') && 
                !nav.contains(e.target) && 
                !menuToggle?.contains(e.target)) {
                nav.classList.remove('open');
                if (menuToggle) menuToggle.classList.remove('active');
                document.body.style.overflow = '';
            }
        });

        // Highlight current page in nav
        this.highlightCurrentNav();
    }

    highlightCurrentNav() {
        const currentPath = window.location.pathname;
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            const href = link.getAttribute('href');
            if (href === currentPath || 
                (href !== '/' && currentPath.includes(href)) ||
                (href === '/' && currentPath === '/')) {
                link.classList.add('active');
            }
        });
    }

    // ============================================
    // SMOOTH SCROLL
    // ============================================
    setupSmoothScroll() {
        if (!this.config.smoothScroll) return;

        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', (e) => {
                const href = anchor.getAttribute('href');
                if (href === '#') return;
                
                const target = document.querySelector(href);
                if (target) {
                    e.preventDefault();
                    const headerHeight = document.getElementById('header')?.offsetHeight || 64;
                    const targetPosition = target.getBoundingClientRect().top + window.scrollY - headerHeight - 20;
                    
                    window.scrollTo({
                        top: targetPosition,
                        behavior: 'smooth'
                    });
                }
            });
        });
    }

    // ============================================
    // SCROLL ANIMATIONS
    // ============================================
    setupScrollAnimations() {
        if (!this.config.animations) return;

        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -40px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target);
                }
            });
        }, observerOptions);

        document.querySelectorAll('.animate, .fade-in-up, .status-card, .feature-card, .step-card, .course-card').forEach(el => {
            observer.observe(el);
        });
    }

    // ============================================
    // HEADER SCROLL EFFECT
    // ============================================
    setupHeaderScroll() {
        const header = document.getElementById('header');
        if (!header) return;

        let lastScroll = 0;
        let scrollTimer;

        window.addEventListener('scroll', () => {
            clearTimeout(scrollTimer);
            
            scrollTimer = setTimeout(() => {
                const currentScroll = window.scrollY;
                
                if (currentScroll > 50) {
                    header.classList.add('scrolled');
                } else {
                    header.classList.remove('scrolled');
                }
                
                lastScroll = currentScroll;
            }, 50);
        }, { passive: true });
    }

    // ============================================
    // KEYBOARD SHORTCUTS
    // ============================================
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl+H = Home
            if (e.ctrlKey && e.key === 'h') {
                e.preventDefault();
                window.location.href = '/';
            }
            
            // Ctrl+D = Dashboard
            if (e.ctrlKey && e.key === 'd') {
                e.preventDefault();
                window.location.href = '/dashboard';
            }
            
            // Ctrl+A = Admin (if admin)
            if (e.ctrlKey && e.key === 'a' && window.AuthGuard?.isAdmin()) {
                e.preventDefault();
                window.location.href = '/admin';
            }
            
            // Escape to close modals
            if (e.key === 'Escape') {
                this.closeAllModals();
            }
        });
    }

    // ============================================
    // EXTERNAL LINKS
    // ============================================
    setupExternalLinks() {
        document.querySelectorAll('a[href^="http"]').forEach(link => {
            if (!link.href.includes(window.location.hostname)) {
                link.setAttribute('rel', 'noopener noreferrer');
                link.setAttribute('target', '_blank');
            }
        });
    }

    // ============================================
    // AUTH STATE CHECK
    // ============================================
    checkAuthState() {
        // Update UI based on auth state
        const isLoggedIn = window.AuthGuard?.isAuthenticated();
        const loginBtns = document.querySelectorAll('.btn-login');
        const logoutBtns = document.querySelectorAll('.btn-logout');
        const userElements = document.querySelectorAll('.user-only');
        const guestElements = document.querySelectorAll('.guest-only');

        loginBtns.forEach(btn => btn.style.display = isLoggedIn ? 'none' : '');
        logoutBtns.forEach(btn => btn.style.display = isLoggedIn ? '' : 'none');
        userElements.forEach(el => el.style.display = isLoggedIn ? '' : 'none');
        guestElements.forEach(el => el.style.display = isLoggedIn ? 'none' : '');

        // Periodically check session
        setInterval(() => {
            if (window.AuthGuard && !window.AuthGuard.isAuthenticated()) {
                const protectedPages = ['/dashboard', '/admin'];
                const currentPath = window.location.pathname;
                if (protectedPages.some(p => currentPath.includes(p))) {
                    window.location.href = '/login';
                }
            }
        }, this.config.sessionCheckInterval);
    }

    // ============================================
    // MODAL MANAGEMENT
    // ============================================
    openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (!modal) return;
        
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
        
        setTimeout(() => modal.classList.add('active'), 10);
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (!modal) return;
        
        modal.classList.remove('active');
        
        setTimeout(() => {
            modal.style.display = 'none';
            document.body.style.overflow = '';
        }, 300);
    }

    closeAllModals() {
        document.querySelectorAll('.modal-overlay.active').forEach(modal => {
            this.closeModal(modal.id);
        });
    }

    // ============================================
    // TOAST NOTIFICATION
    // ============================================
    showToast(message, type = 'info') {
        const existingToast = document.querySelector('.toast-notification');
        if (existingToast) existingToast.remove();

        const toast = document.createElement('div');
        toast.className = `toast-notification toast-${type}`;
        
        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };
        
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || icons.info}</span>
            <span class="toast-message">${this.escapeHTML(message)}</span>
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, this.config.toastDuration);
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================
    getCurrentPage() {
        const path = window.location.pathname;
        const page = path.split('/').pop() || 'index';
        return page.replace('.html', '');
    }

    escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    debounce(func, wait = 300) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    throttle(func, limit = 300) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    formatDate(date, format = 'long') {
        const d = new Date(date);
        if (isNaN(d.getTime())) return 'Invalid date';
        
        const options = {
            short: { day: 'numeric', month: 'short', year: 'numeric' },
            long: { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' },
            time: { hour: '2-digit', minute: '2-digit' },
            datetime: { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }
        };
        
        return d.toLocaleDateString('en-IN', options[format] || options.long);
    }

    formatNumber(num) {
        return new Intl.NumberFormat('en-IN').format(num);
    }

    getURLParameter(name) {
        const params = new URLSearchParams(window.location.search);
        return params.get(name);
    }

    setURLParameter(name, value) {
        const params = new URLSearchParams(window.location.search);
        params.set(name, value);
        window.history.replaceState({}, '', `${window.location.pathname}?${params}`);
    }

    // ============================================
    // STORAGE HELPERS
    // ============================================
    storage = {
        set(key, value) {
            try {
                localStorage.setItem(key, JSON.stringify(value));
                return true;
            } catch (e) {
                console.error('Storage set error:', e);
                return false;
            }
        },
        get(key) {
            try {
                const item = localStorage.getItem(key);
                return item ? JSON.parse(item) : null;
            } catch (e) {
                return null;
            }
        },
        remove(key) {
            localStorage.removeItem(key);
        },
        clear() {
            localStorage.clear();
        }
    };

    // ============================================
    // LOGGING
    // ============================================
    log(message, level = 'info') {
        if (!this.config.debug && level === 'debug') return;
        
        const prefix = {
            debug: '🔍',
            info: 'ℹ️',
            warn: '⚠️',
            error: '❌'
        }[level] || '📋';
        
        console.log(`${prefix} [App] ${message}`);
    }

    // ============================================
    // ERROR HANDLING
    // ============================================
    handleError(error, context = '') {
        console.error(`❌ [App Error] ${context}:`, error);
        
        if (window.Logger) {
            Logger.logError(error, { context });
        }
        
        if (this.config.debug) {
            this.showToast(`Error: ${error.message}`, 'error');
        }
    }

    // ============================================
    // GET APP STATUS
    // ============================================
    getStatus() {
        return {
            version: this.version,
            initialized: this.initialized,
            currentPage: this.currentPage,
            uptime: Date.now() - this.startTime,
            online: navigator.onLine,
            userAgent: navigator.userAgent.substring(0, 100),
            screenSize: `${window.innerWidth}x${window.innerHeight}`,
            securityModules: {
                security: !!window.Security,
                firewall: !!window.Firewall,
                validator: !!window.Validator,
                authGuard: !!window.AuthGuard,
                rateLimiter: !!window.RateLimiter,
                encryption: !!window.Encryption,
                headers: !!window.SecurityHeaders,
                logger: !!window.Logger
            }
        };
    }

    // ============================================
    // CLEANUP
    // ============================================
    destroy() {
        this.initialized = false;
        this.log('App destroyed');
    }
}

// ============================================
// INITIALIZE GLOBAL APP INSTANCE
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    window.App = new App();
    
    // Log app ready
    console.log('🚀 Secure Website v' + window.App.version + ' Ready');
    console.log('✅ All systems operational');
});
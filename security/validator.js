// ============================================
// SECURE WEBSITE — Input Validator Module v2.0
// Data Validation, Sanitization & Formatting
// ============================================

class Validator {
    constructor() {
        this.maxStringLength = 5000;
        this.maxEmailLength = 254;
        this.maxPhoneLength = 20;
        this.maxURLlength = 2048;
        this.passwordMinLength = 8;
        this.passwordMaxLength = 128;
        this.allowedFileTypes = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'image/svg+xml', 'application/pdf', 'text/plain',
            'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        this.maxFileSize = 10 * 1024 * 1024; // 10MB
        this.blockedExtensions = ['.exe', '.bat', '.cmd', '.sh', '.bash', '.php', '.asp', '.jsp', '.py', '.pl'];
        
        console.log('✅ Validator Module Loaded');
    }

    // ============================================
    // MAIN SANITIZATION
    // ============================================
    sanitize(input, type = 'text') {
        if (input === null || input === undefined) return '';
        if (typeof input !== 'string') input = String(input);
        
        let sanitized = input;
        
        // Remove null bytes
        sanitized = sanitized.replace(/\0/g, '');
        
        // Remove HTML tags (always)
        sanitized = sanitized.replace(/<[^>]*>/g, '');
        
        // Remove JavaScript event handlers
        sanitized = sanitized.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
        sanitized = sanitized.replace(/on\w+\s*=\s*[^\s>]*/gi, '');
        
        // Remove javascript: URLs
        sanitized = sanitized.replace(/javascript\s*:/gi, '');
        
        // Remove CSS expressions
        sanitized = sanitized.replace(/expression\s*\(/gi, '');
        
        // Remove SQL injection patterns
        sanitized = sanitized
            .replace(/--/g, '')
            .replace(/\/\*/g, '')
            .replace(/\*\//g, '')
            .replace(/;\s*$/g, '');
        
        // Remove extra whitespace
        sanitized = sanitized.replace(/\s+/g, ' ').trim();
        
        // Type-specific sanitization
        switch(type.toLowerCase()) {
            case 'email':
                sanitized = sanitized.toLowerCase().replace(/[^a-z0-9@._+\-]/g, '');
                sanitized = sanitized.substring(0, this.maxEmailLength);
                break;
                
            case 'phone':
                sanitized = sanitized.replace(/[^\d+\-()\s]/g, '');
                sanitized = sanitized.substring(0, this.maxPhoneLength);
                break;
                
            case 'url':
                sanitized = sanitized.replace(/[^\w\-\.\/:?=&@%#+]/g, '');
                sanitized = sanitized.substring(0, this.maxURLlength);
                break;
                
            case 'number':
            case 'integer':
                sanitized = sanitized.replace(/[^\d.\-eE]/g, '');
                if (type === 'integer') {
                    sanitized = sanitized.replace(/[.\-eE]/g, '');
                }
                break;
                
            case 'alpha':
                sanitized = sanitized.replace(/[^a-zA-Z\s]/g, '');
                break;
                
            case 'alphanumeric':
                sanitized = sanitized.replace(/[^a-zA-Z0-9\s]/g, '');
                break;
                
            case 'username':
                sanitized = sanitized.replace(/[^a-zA-Z0-9_\-.]/g, '');
                sanitized = sanitized.substring(0, 30);
                break;
                
            case 'name':
                sanitized = sanitized.replace(/[^a-zA-Z\s\-'.]/g, '');
                sanitized = sanitized.substring(0, 100);
                break;
                
            case 'filename':
                sanitized = sanitized.replace(/[^a-zA-Z0-9_\-.]/g, '');
                sanitized = sanitized.substring(0, 255);
                break;
                
            case 'hex':
                sanitized = sanitized.replace(/[^a-fA-F0-9]/g, '');
                break;
                
            case 'base64':
                sanitized = sanitized.replace(/[^a-zA-Z0-9+/=]/g, '');
                break;
                
            case 'html':
                // Allow some safe HTML tags
                sanitized = this.sanitizeHTML(sanitized);
                break;
                
            default:
                // General text - remove special chars
                sanitized = sanitized.replace(/[<>"'`]/g, '');
                sanitized = sanitized.substring(0, this.maxStringLength);
        }
        
        return sanitized;
    }

    // ============================================
    // HTML SANITIZATION (Allow safe tags only)
    // ============================================
    sanitizeHTML(html) {
        const allowedTags = ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'a', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
        const allowedAttrs = ['href', 'title', 'alt', 'class', 'id', 'target'];
        
        // Create a temporary DOM element
        const temp = document.createElement('div');
        temp.textContent = html; // First escape everything
        let clean = temp.innerHTML;
        
        // Then selectively unescape allowed tags
        allowedTags.forEach(tag => {
            const openRegex = new RegExp(`&lt;${tag}(\\s[^&]*)?&gt;`, 'gi');
            const closeRegex = new RegExp(`&lt;/${tag}&gt;`, 'gi');
            
            clean = clean.replace(openRegex, (match) => {
                let tagMatch = match.replace(/&lt;/g, '<').replace(/&gt;/g, '>');
                // Remove unsafe attributes
                tagMatch = tagMatch.replace(/(\w+)=["'][^"']*["']/g, (attrMatch) => {
                    const attrName = attrMatch.split('=')[0].toLowerCase();
                    return allowedAttrs.includes(attrName) ? attrMatch : '';
                });
                return tagMatch;
            });
            
            clean = clean.replace(closeRegex, `</${tag}>`);
        });
        
        return clean.substring(0, this.maxStringLength);
    }

    // ============================================
    // VALIDATION FUNCTIONS
    // ============================================
    
    validateEmail(email) {
        if (!email || typeof email !== 'string') return false;
        if (email.length > this.maxEmailLength) return false;
        
        // RFC 5322 compliant regex
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        
        if (!emailRegex.test(email)) return false;
        
        // Additional checks
        if (email.startsWith('.') || email.endsWith('.')) return false;
        if (email.includes('..')) return false;
        if (email.includes('@') && email.split('@')[0].length === 0) return false;
        
        // Check domain has dot
        const domain = email.split('@')[1];
        if (!domain || !domain.includes('.')) return false;
        
        // Check for disposable emails (optional)
        const disposableDomains = ['mailinator.com', 'guerrillamail.com', 'tempmail.com', '10minutemail.com', 'yopmail.com', 'throwaway.email', 'sharklasers.com', 'trashmail.com'];
        const domainLower = domain.toLowerCase();
        if (disposableDomains.includes(domainLower)) return false;
        
        return true;
    }

    validatePhone(phone) {
        if (!phone || typeof phone !== 'string') return false;
        
        // Remove all non-digit characters for counting
        const digits = phone.replace(/\D/g, '');
        if (digits.length < 10 || digits.length > 15) return false;
        
        // Check for valid format
        const phoneRegex = /^[+]?[\d\s()\-.]{10,20}$/;
        return phoneRegex.test(phone);
    }

    validateURL(url) {
        if (!url || typeof url !== 'string') return false;
        if (url.length > this.maxURLlength) return false;
        
        try {
            const parsed = new URL(url);
            
            // Only allow http and https
            if (!['http:', 'https:'].includes(parsed.protocol)) return false;
            
            // Must have a valid hostname
            if (!parsed.hostname || parsed.hostname.length < 3) return false;
            if (!parsed.hostname.includes('.')) return false;
            
            // Block localhost and internal IPs
            const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]'];
            if (blockedHosts.includes(parsed.hostname)) return false;
            
            // Check for private IPs
            if (/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(parsed.hostname)) return false;
            
            return true;
        } catch {
            return false;
        }
    }

    validatePassword(password) {
        if (!password || typeof password !== 'string') return false;
        if (password.length < this.passwordMinLength) return false;
        if (password.length > this.passwordMaxLength) return false;
        
        // Check complexity
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumber = /\d/.test(password);
        const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password);
        
        // Require at least 3 of 4 character types
        const complexityScore = [hasUpper, hasLower, hasNumber, hasSpecial].filter(Boolean).length;
        if (complexityScore < 3) return false;
        
        // Check for common passwords
        const commonPasswords = ['password', 'password123', '12345678', 'qwerty123', 'admin123', 'letmein', 'welcome', 'monkey', 'dragon', 'master', 'football', 'baseball', 'abc123', '11111111', 'iloveyou', 'trustno1', 'sunshine', 'princess'];
        if (commonPasswords.includes(password.toLowerCase())) return false;
        
        // Check for sequential characters
        const sequences = ['abcdefgh', '12345678', 'qwertyui', 'asdfghjk', 'zxcvbnm'];
        for (const seq of sequences) {
            if (password.toLowerCase().includes(seq)) return false;
        }
        
        return true;
    }

    validateFile(file) {
        if (!file) return { valid: false, error: 'No file provided' };
        
        // Check file size
        if (file.size > this.maxFileSize) {
            return { valid: false, error: `File too large. Maximum ${this.maxFileSize / 1024 / 1024}MB allowed.` };
        }
        
        if (file.size === 0) {
            return { valid: false, error: 'File is empty.' };
        }
        
        // Check file type
        if (!this.allowedFileTypes.includes(file.type)) {
            return { valid: false, error: `File type "${file.type}" not allowed.` };
        }
        
        // Check extension
        const fileName = file.name || '';
        const extension = '.' + fileName.split('.').pop()?.toLowerCase();
        
        if (this.blockedExtensions.includes(extension)) {
            return { valid: false, error: `File extension "${extension}" is blocked.` };
        }
        
        // Double extension check
        if (fileName.split('.').length > 3) {
            return { valid: false, error: 'Multiple file extensions not allowed.' };
        }
        
        // Check filename length
        if (fileName.length > 255) {
            return { valid: false, error: 'Filename too long.' };
        }
        
        return { valid: true };
    }

    // ============================================
    // COMPREHENSIVE VALIDATION
    // ============================================
    validate(input, rules = []) {
        const errors = [];
        const value = input !== undefined && input !== null ? String(input) : '';
        
        for (const rule of rules) {
            switch(rule.type) {
                case 'required':
                    if (!value || value.trim() === '') {
                        errors.push(rule.message || 'This field is required.');
                    }
                    break;
                    
                case 'minLength':
                    if (value.length < rule.value) {
                        errors.push(rule.message || `Minimum ${rule.value} characters required.`);
                    }
                    break;
                    
                case 'maxLength':
                    if (value.length > rule.value) {
                        errors.push(rule.message || `Maximum ${rule.value} characters allowed.`);
                    }
                    break;
                    
                case 'email':
                    if (value && !this.validateEmail(value)) {
                        errors.push(rule.message || 'Invalid email address.');
                    }
                    break;
                    
                case 'phone':
                    if (value && !this.validatePhone(value)) {
                        errors.push(rule.message || 'Invalid phone number.');
                    }
                    break;
                    
                case 'url':
                    if (value && !this.validateURL(value)) {
                        errors.push(rule.message || 'Invalid URL.');
                    }
                    break;
                    
                case 'password':
                    if (!this.validatePassword(value)) {
                        errors.push(rule.message || 'Password does not meet requirements.');
                    }
                    break;
                    
                case 'pattern':
                    if (value && !new RegExp(rule.value).test(value)) {
                        errors.push(rule.message || 'Invalid format.');
                    }
                    break;
                    
                case 'match':
                    if (value !== rule.value) {
                        errors.push(rule.message || 'Values do not match.');
                    }
                    break;
                    
                case 'min':
                    if (parseFloat(value) < rule.value) {
                        errors.push(rule.message || `Minimum value is ${rule.value}.`);
                    }
                    break;
                    
                case 'max':
                    if (parseFloat(value) > rule.value) {
                        errors.push(rule.message || `Maximum value is ${rule.value}.`);
                    }
                    break;
                    
                case 'in':
                    if (!rule.values.includes(value)) {
                        errors.push(rule.message || 'Invalid selection.');
                    }
                    break;
                    
                case 'custom':
                    if (typeof rule.fn === 'function' && !rule.fn(value)) {
                        errors.push(rule.message || 'Validation failed.');
                    }
                    break;
            }
        }
        
        return {
            valid: errors.length === 0,
            errors: errors
        };
    }

    // ============================================
    // FORMAT HELPERS
    // ============================================
    formatPhone(phone) {
        const digits = phone.replace(/\D/g, '');
        if (digits.length === 10) {
            return `+91 ${digits.substring(0, 5)} ${digits.substring(5)}`;
        }
        return phone;
    }

    formatCurrency(amount, currency = 'INR') {
        const num = parseFloat(amount);
        if (isNaN(num)) return '₹0.00';
        
        return new Intl.NumberFormat('en-IN', {
            style: 'currency',
            currency: currency
        }).format(num);
    }

    formatDate(date, format = 'long') {
        const d = new Date(date);
        if (isNaN(d.getTime())) return 'Invalid date';
        
        switch(format) {
            case 'short':
                return d.toLocaleDateString('en-IN');
            case 'long':
                return d.toLocaleDateString('en-IN', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
            case 'time':
                return d.toLocaleTimeString('en-IN');
            case 'datetime':
                return d.toLocaleString('en-IN');
            default:
                return d.toISOString();
        }
    }

    truncate(text, length = 100, suffix = '...') {
        if (!text) return '';
        if (text.length <= length) return text;
        return text.substring(0, length).trim() + suffix;
    }

    slugify(text) {
        return text
            .toString()
            .toLowerCase()
            .trim()
            .replace(/\s+/g, '-')
            .replace(/[^\w\-]+/g, '')
            .replace(/\-\-+/g, '-')
            .replace(/^-+/, '')
            .replace(/-+$/, '');
    }

    // ============================================
    // CREDIT CARD VALIDATION (Basic)
    // ============================================
    validateCreditCard(number) {
        const digits = number.replace(/\D/g, '');
        if (digits.length < 13 || digits.length > 19) return false;
        
        // Luhn algorithm
        let sum = 0;
        let alternate = false;
        
        for (let i = digits.length - 1; i >= 0; i--) {
            let n = parseInt(digits.charAt(i), 10);
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        
        return sum % 10 === 0;
    }

    // ============================================
    // MASK SENSITIVE DATA
    // ============================================
    maskEmail(email) {
        if (!email || !email.includes('@')) return '***@***.***';
        const [name, domain] = email.split('@');
        const maskedName = name.charAt(0) + '***' + name.charAt(name.length - 1);
        return maskedName + '@' + domain;
    }

    maskPhone(phone) {
        const digits = phone.replace(/\D/g, '');
        if (digits.length < 4) return '****';
        return '****' + digits.slice(-4);
    }

    maskCreditCard(number) {
        const digits = number.replace(/\D/g, '');
        return '****-****-****-' + digits.slice(-4);
    }
}

// ============================================
// INITIALIZE GLOBAL VALIDATOR INSTANCE
// ============================================
window.Validator = new Validator();
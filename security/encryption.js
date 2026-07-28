// ============================================
// SECURE WEBSITE — Encryption Module v2.0
// Data Encryption, Hashing & Secure Storage
// ============================================

class Encryption {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
        this.hashAlgorithm = 'SHA-256';
        this.iterations = 100000;
        this.saltLength = 16;
        this.ivLength = 12;
        
        // Default encryption key (change in production!)
        this.defaultKey = 'secure-website-encryption-key-v2';
        
        this.initialized = false;
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    async init() {
        try {
            // Test crypto API availability
            await crypto.subtle.digest('SHA-256', new TextEncoder().encode('test'));
            this.initialized = true;
            console.log('🔒 Encryption Module Loaded');
        } catch (error) {
            console.error('Encryption initialization failed:', error);
        }
    }

    // ============================================
    // KEY DERIVATION
    // ============================================
    async deriveKey(password, salt = null) {
        if (!salt) {
            salt = crypto.getRandomValues(new Uint8Array(this.saltLength));
        }

        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password || this.defaultKey),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.iterations,
                hash: this.hashAlgorithm
            },
            keyMaterial,
            {
                name: this.algorithm,
                length: this.keyLength
            },
            false,
            ['encrypt', 'decrypt']
        );

        return { key, salt };
    }

    // ============================================
    // ENCRYPTION
    // ============================================
    async encrypt(data, password = null) {
        if (!this.initialized) {
            console.error('Encryption module not initialized');
            return null;
        }

        try {
            const { key, salt } = await this.deriveKey(password);
            const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
            const encoder = new TextEncoder();
            const encodedData = encoder.encode(typeof data === 'string' ? data : JSON.stringify(data));

            const encrypted = await crypto.subtle.encrypt(
                {
                    name: this.algorithm,
                    iv: iv
                },
                key,
                encodedData
            );

            // Return combined data: salt + iv + ciphertext
            const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            combined.set(salt, 0);
            combined.set(iv, salt.length);
            combined.set(new Uint8Array(encrypted), salt.length + iv.length);

            return this.arrayBufferToBase64(combined);
        } catch (error) {
            console.error('Encryption error:', error);
            return null;
        }
    }

    // ============================================
    // DECRYPTION
    // ============================================
    async decrypt(encryptedData, password = null) {
        if (!this.initialized) {
            console.error('Encryption module not initialized');
            return null;
        }

        try {
            const combined = this.base64ToArrayBuffer(encryptedData);
            
            // Extract salt, iv, and ciphertext
            const salt = combined.slice(0, this.saltLength);
            const iv = combined.slice(this.saltLength, this.saltLength + this.ivLength);
            const ciphertext = combined.slice(this.saltLength + this.ivLength);

            const { key } = await this.deriveKey(password, salt);

            const decrypted = await crypto.subtle.decrypt(
                {
                    name: this.algorithm,
                    iv: iv
                },
                key,
                ciphertext
            );

            const decoder = new TextDecoder();
            const decodedData = decoder.decode(decrypted);

            // Try to parse as JSON
            try {
                return JSON.parse(decodedData);
            } catch {
                return decodedData;
            }
        } catch (error) {
            console.error('Decryption error:', error);
            return null;
        }
    }

    // ============================================
    // HASHING
    // ============================================
    async hash(data) {
        if (!this.initialized) return null;

        try {
            const encoder = new TextEncoder();
            const encoded = encoder.encode(typeof data === 'string' ? data : JSON.stringify(data));
            const hashBuffer = await crypto.subtle.digest(this.hashAlgorithm, encoded);
            
            return this.arrayBufferToHex(hashBuffer);
        } catch (error) {
            console.error('Hash error:', error);
            return null;
        }
    }

    async hashWithSalt(data, salt = null) {
        if (!salt) {
            salt = crypto.getRandomValues(new Uint8Array(16));
        }

        const encoder = new TextEncoder();
        const combined = encoder.encode(
            (typeof data === 'string' ? data : JSON.stringify(data)) + 
            this.arrayBufferToHex(salt)
        );
        
        const hashBuffer = await crypto.subtle.digest(this.hashAlgorithm, combined);
        
        return {
            hash: this.arrayBufferToHex(hashBuffer),
            salt: this.arrayBufferToHex(salt)
        };
    }

    async verifyHash(data, hash, salt) {
        const result = await this.hashWithSalt(data, this.hexToArrayBuffer(salt));
        return result.hash === hash;
    }

    // ============================================
    // SECURE RANDOM GENERATION
    // ============================================
    generateRandomBytes(length = 32) {
        const bytes = crypto.getRandomValues(new Uint8Array(length));
        return this.arrayBufferToHex(bytes);
    }

    generateUUID() {
        return crypto.randomUUID();
    }

    generateToken(length = 32) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const bytes = crypto.getRandomValues(new Uint8Array(length));
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars[bytes[i] % chars.length];
        }
        return result;
    }

    // ============================================
    // BASE64 ENCODING
    // ============================================
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    // ============================================
    // HEX ENCODING
    // ============================================
    arrayBufferToHex(buffer) {
        const bytes = new Uint8Array(buffer);
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    hexToArrayBuffer(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    // ============================================
    // SECURE STORAGE
    // ============================================
    async secureStore(key, value, password = null) {
        const encrypted = await this.encrypt(value, password);
        if (encrypted) {
            localStorage.setItem('enc_' + key, encrypted);
            return true;
        }
        return false;
    }

    async secureRetrieve(key, password = null) {
        const encrypted = localStorage.getItem('enc_' + key);
        if (!encrypted) return null;
        return await this.decrypt(encrypted, password);
    }

    secureRemove(key) {
        localStorage.removeItem('enc_' + key);
    }

    // ============================================
    // PASSWORD UTILITIES
    // ============================================
    generatePassword(length = 16, options = {}) {
        const defaults = {
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            excludeSimilar: true
        };

        const opts = { ...defaults, ...options };
        
        let chars = '';
        if (opts.lowercase) chars += 'abcdefghjkmnpqrstuvwxyz'; // Exclude i, l, o
        if (opts.uppercase) chars += 'ABCDEFGHJKMNPQRSTUVWXYZ'; // Exclude I, L, O
        if (opts.numbers) chars += '23456789'; // Exclude 0, 1
        if (opts.symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        const bytes = crypto.getRandomValues(new Uint8Array(length));
        let password = '';
        
        for (let i = 0; i < length; i++) {
            password += chars[bytes[i] % chars.length];
        }

        // Ensure at least one of each required type
        if (opts.lowercase && !/[a-z]/.test(password)) {
            password = password.slice(0, -1) + 'a';
        }
        if (opts.uppercase && !/[A-Z]/.test(password)) {
            password = password.slice(0, -1) + 'A';
        }
        if (opts.numbers && !/[0-9]/.test(password)) {
            password = password.slice(0, -1) + '5';
        }
        if (opts.symbols && !/[^a-zA-Z0-9]/.test(password)) {
            password = password.slice(0, -1) + '!';
        }

        return password;
    }

    checkPasswordStrength(password) {
        let score = 0;
        const feedback = [];

        if (password.length >= 12) score += 2;
        else if (password.length >= 8) score += 1;
        else feedback.push('Password should be at least 8 characters.');

        if (/[A-Z]/.test(password)) score += 1;
        else feedback.push('Add uppercase letters.');

        if (/[a-z]/.test(password)) score += 1;
        else feedback.push('Add lowercase letters.');

        if (/[0-9]/.test(password)) score += 1;
        else feedback.push('Add numbers.');

        if (/[^a-zA-Z0-9]/.test(password)) score += 1;
        else feedback.push('Add special characters.');

        if (/(.)\1{2,}/.test(password)) {
            score -= 1;
            feedback.push('Avoid repeating characters.');
        }

        let strength;
        if (score >= 5) strength = 'strong';
        else if (score >= 3) strength = 'medium';
        else strength = 'weak';

        return { score, strength, feedback };
    }

    // ============================================
    // DATA MASKING
    // ============================================
    maskSensitive(data, type = 'default') {
        if (!data) return '***';

        switch (type) {
            case 'email':
                const [name, domain] = data.split('@');
                if (!domain) return '***@***.***';
                return name.charAt(0) + '***' + '@' + domain;
                
            case 'phone':
                const digits = data.replace(/\D/g, '');
                return '*******' + digits.slice(-3);
                
            case 'card':
                const cardDigits = data.replace(/\D/g, '');
                return '****-****-****-' + cardDigits.slice(-4);
                
            case 'name':
                return data.charAt(0) + '***' + data.charAt(data.length - 1);
                
            default:
                if (data.length <= 4) return '***';
                return data.substring(0, 2) + '***' + data.substring(data.length - 2);
        }
    }

    // ============================================
    // DIGITAL SIGNATURE (HMAC)
    // ============================================
    async sign(data, key = null) {
        try {
            const encoder = new TextEncoder();
            const keyData = encoder.encode(key || this.defaultKey);
            
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'HMAC', hash: this.hashAlgorithm },
                false,
                ['sign']
            );

            const signature = await crypto.subtle.sign(
                'HMAC',
                cryptoKey,
                encoder.encode(typeof data === 'string' ? data : JSON.stringify(data))
            );

            return this.arrayBufferToHex(signature);
        } catch (error) {
            console.error('Sign error:', error);
            return null;
        }
    }

    async verify(data, signature, key = null) {
        const expectedSignature = await this.sign(data, key);
        return expectedSignature === signature;
    }

    // ============================================
    // CLEANUP
    // ============================================
    destroy() {
        this.initialized = false;
        console.log('Encryption module destroyed');
    }
}

// ============================================
// INITIALIZE GLOBAL ENCRYPTION INSTANCE
// ============================================
window.Encryption = new Encryption();
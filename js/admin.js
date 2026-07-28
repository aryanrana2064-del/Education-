// ============================================
// SECURE WEBSITE — Admin Panel Logic v2.0
// User Management, Settings & Controls
// ============================================

class AdminPanel {
    constructor() {
        this.initialized = false;
        this.currentTab = 'users';
        this.users = [];
        this.orders = [];
        this.settings = {};
        
        this.init();
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    init() {
        // Check admin access
        if (!this.checkAccess()) return;

        this.loadData();
        this.setupTabs();
        this.setupSearch();
        this.setupEventListeners();
        this.refreshStats();
        
        this.initialized = true;
        console.log('👑 Admin Panel Loaded');
    }

    // ============================================
    // ACCESS CHECK
    // ============================================
    checkAccess() {
        if (typeof AuthGuard !== 'undefined' && !AuthGuard.isAdmin()) {
            window.location.href = '/login';
            return false;
        }
        return true;
    }

    // ============================================
    // DATA LOADING
    // ============================================
    loadData() {
        this.loadUsers();
        this.loadSettings();
        this.updateDashboard();
    }

    loadUsers() {
        // Demo users
        this.users = [
            { id: 1, name: 'Admin User', email: 'admin@securesite.com', role: 'admin', status: 'active', lastLogin: '2 min ago', joined: '2026-01-01' },
            { id: 2, name: 'John Doe', email: 'john@example.com', role: 'user', status: 'active', lastLogin: '1 hour ago', joined: '2026-01-15' },
            { id: 3, name: 'Jane Smith', email: 'jane@example.com', role: 'user', status: 'active', lastLogin: '3 hours ago', joined: '2026-02-01' },
            { id: 4, name: 'Bob Wilson', email: 'bob@example.com', role: 'moderator', status: 'blocked', lastLogin: '3 days ago', joined: '2025-12-10' },
            { id: 5, name: 'Alice Brown', email: 'alice@example.com', role: 'user', status: 'active', lastLogin: '5 min ago', joined: '2026-03-01' }
        ];

        this.renderUsersTable();
    }

    loadSettings() {
        this.settings = {
            firewall: true,
            rateLimit: true,
            auditLog: true,
            maintenance: false,
            autoBlock: true,
            maxRequests: 100,
            loginAttempts: 5,
            blockDuration: 15
        };

        this.renderSettings();
    }

    // ============================================
    // TAB MANAGEMENT
    // ============================================
    setupTabs() {
        document.querySelectorAll('.admin-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.dataset.tab;
                this.switchTab(tabName, tab);
            });
        });
    }

    switchTab(tabName, tabElement) {
        // Update active tab
        document.querySelectorAll('.admin-tab').forEach(t => t.classList.remove('active'));
        if (tabElement) tabElement.classList.add('active');

        // Show content
        document.querySelectorAll('.admin-tab-content').forEach(c => c.classList.remove('active'));
        const content = document.getElementById('tab-' + tabName);
        if (content) content.classList.add('active');

        this.currentTab = tabName;
        
        // Refresh specific tab content
        this.refreshTab(tabName);
    }

    refreshTab(tabName) {
        switch(tabName) {
            case 'users': this.renderUsersTable(); break;
            case 'security': this.refreshSecurityTab(); break;
            case 'logs': this.refreshLogs(); break;
            case 'settings': this.renderSettings(); break;
        }
    }

    // ============================================
    // DASHBOARD STATS
    // ============================================
    updateDashboard() {
        this.updateStats();
        this.renderUsersTable();
        this.refreshLogs();
    }

    updateStats() {
        const stats = {
            statTotalUsers: this.users.length,
            statActiveUsers: this.users.filter(u => u.status === 'active').length,
            statBlockedIPs: window.Firewall?.getStats()?.blockedIPs || 0,
            statThreatLevel: window.Security?.getStatus()?.threatLevel || 'Low',
            statUptime: Math.floor((Date.now() - (window.Security?.startTime || Date.now())) / 3600000) + 'h'
        };

        Object.entries(stats).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        });
    }

    refreshStats() {
        this.updateStats();
        setTimeout(() => this.refreshStats(), 10000);
    }

    // ============================================
    // USERS TABLE
    // ============================================
    renderUsersTable(filter = '') {
        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;

        let filteredUsers = this.users;
        if (filter) {
            const query = filter.toLowerCase();
            filteredUsers = this.users.filter(u => 
                u.name.toLowerCase().includes(query) || 
                u.email.toLowerCase().includes(query)
            );
        }

        tbody.innerHTML = filteredUsers.map(user => `
            <tr>
                <td>#${user.id}</td>
                <td>
                    <div class="user-cell">
                        <div class="user-avatar-sm">${user.name.charAt(0)}</div>
                        <span>${this.escapeHTML(user.name)}</span>
                    </div>
                </td>
                <td>${this.escapeHTML(user.email)}</td>
                <td><span class="badge badge-blue">${user.role}</span></td>
                <td>
                    <span class="badge ${user.status === 'active' ? 'badge-green' : 'badge-red'}">
                        ${user.status}
                    </span>
                </td>
                <td>${user.lastLogin}</td>
                <td>
                    <div class="action-btns">
                        <button class="btn btn-sm btn-outline" onclick="AdminPanel.editUser(${user.id})" title="Edit">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-sm btn-outline" onclick="AdminPanel.toggleUserStatus(${user.id})" title="Toggle Status">
                            <i class="fas fa-power-off"></i>
                        </button>
                        <button class="btn btn-sm btn-red" onclick="AdminPanel.deleteUser(${user.id})" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    // ============================================
    // USER ACTIONS
    // ============================================
    editUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return;

        const newName = prompt('Edit name:', user.name);
        if (newName && newName.trim()) {
            user.name = this.escapeHTML(newName.trim());
            this.renderUsersTable();
            this.showToast('User updated successfully!', 'success');
            this.logAction('user_edited', { userId, newName });
        }
    }

    toggleUserStatus(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return;

        user.status = user.status === 'active' ? 'blocked' : 'active';
        this.renderUsersTable();
        this.showToast(`User ${user.status === 'active' ? 'activated' : 'blocked'}!`, 'success');
        this.logAction('user_status_changed', { userId, newStatus: user.status });
    }

    deleteUser(userId) {
        if (!confirm('Are you sure you want to delete this user?')) return;

        this.users = this.users.filter(u => u.id !== userId);
        this.renderUsersTable();
        this.updateStats();
        this.showToast('User deleted!', 'success');
        this.logAction('user_deleted', { userId });
    }

    // ============================================
    // SEARCH
    // ============================================
    setupSearch() {
        const searchInput = document.getElementById('userSearchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.renderUsersTable(e.target.value);
            });
        }
    }

    // ============================================
    // SECURITY TAB
    // ============================================
    refreshSecurityTab() {
        this.loadBlockedIPs();
    }

    loadBlockedIPs() {
        const list = document.getElementById('blockedIPList');
        if (!list) return;

        const blockedIPs = window.Firewall?.getBlockedIPs() || [];
        
        list.innerHTML = blockedIPs.length > 0 ? 
            blockedIPs.map(ip => `
                <div class="blocked-ip-item">
                    <span>🚫 ${ip}</span>
                    <button class="btn btn-sm btn-outline" onclick="AdminPanel.unblockIP('${ip}')">Unblock</button>
                </div>
            `).join('') : 
            '<p class="text-muted">No IPs currently blocked.</p>';
    }

    blockNewIP() {
        const input = document.getElementById('blockIPInput');
        if (!input) return;

        const ip = input.value.trim();
        if (!ip) {
            this.showToast('Please enter an IP address.', 'error');
            return;
        }

        if (window.Firewall) {
            window.Firewall.blockIP(ip);
        }

        input.value = '';
        this.loadBlockedIPs();
        this.updateStats();
        this.showToast(`IP ${ip} blocked!`, 'success');
        this.logAction('ip_blocked', { ip });
    }

    unblockIP(ip) {
        if (window.Firewall) {
            window.Firewall.unblockIP(ip);
        }
        this.loadBlockedIPs();
        this.updateStats();
        this.showToast(`IP ${ip} unblocked!`, 'success');
        this.logAction('ip_unblocked', { ip });
    }

    // ============================================
    // LOGS
    // ============================================
    refreshLogs() {
        const container = document.getElementById('auditLogContainer');
        if (!container) return;

        const logs = window.Logger?.getLogs(20) || [];
        
        container.innerHTML = logs.length > 0 ?
            logs.map(log => `
                <div class="log-entry">
                    <span>${this.escapeHTML(log.action)}</span>
                    <span class="log-time">${new Date(log.timestamp).toLocaleTimeString()}</span>
                </div>
            `).join('') :
            '<p class="text-muted">No audit logs available.</p>';
    }

    clearAllLogs() {
        if (!confirm('Clear all audit logs?')) return;
        
        if (window.Logger) {
            window.Logger.clearLogs();
        }
        this.refreshLogs();
        this.showToast('Logs cleared!', 'success');
    }

    filterLogs() {
        const filter = document.getElementById('logFilter')?.value || 'all';
        const container = document.getElementById('auditLogContainer');
        if (!container) return;

        let logs = window.Logger?.getLogs(100) || [];
        
        if (filter !== 'all') {
            logs = logs.filter(l => l.category === filter || l.action.includes(filter));
        }

        container.innerHTML = logs.length > 0 ?
            logs.map(log => `
                <div class="log-entry">
                    <span>${this.escapeHTML(log.action)}</span>
                    <span class="log-time">${new Date(log.timestamp).toLocaleTimeString()}</span>
                </div>
            `).join('') :
            '<p class="text-muted">No matching logs.</p>';
    }

    // ============================================
    // SETTINGS
    // ============================================
    renderSettings() {
        // Load current settings into form
        Object.entries(this.settings).forEach(([key, value]) => {
            const el = document.getElementById(key + 'Toggle') || 
                       document.getElementById(key + 'Input');
            if (el) {
                if (el.type === 'checkbox') {
                    el.checked = value;
                } else {
                    el.value = value;
                }
            }
        });
    }

    toggleSystemSetting(setting) {
        const toggle = document.getElementById(setting + 'Toggle');
        if (toggle) {
            this.settings[setting] = toggle.checked;
            this.logAction('setting_changed', { setting, value: toggle.checked });
        }
    }

    saveAllSettings() {
        // Save rate limit settings
        const maxRequests = document.getElementById('rateLimitMax')?.value;
        const loginAttempts = document.getElementById('loginLimitMax')?.value;
        const blockDuration = document.getElementById('blockDuration')?.value;

        if (maxRequests) this.settings.maxRequests = parseInt(maxRequests);
        if (loginAttempts) this.settings.loginAttempts = parseInt(loginAttempts);
        if (blockDuration) this.settings.blockDuration = parseInt(blockDuration);

        this.showToast('All settings saved!', 'success');
        this.logAction('settings_saved', this.settings);
    }

    // ============================================
    // BACKUP
    // ============================================
    createBackup() {
        this.showToast('Creating backup...', 'info');
        
        setTimeout(() => {
            this.showToast('Backup created successfully!', 'success');
            this.logAction('backup_created');
        }, 2000);
    }

    restoreBackup() {
        if (!confirm('Restore from backup? Current data may be overwritten.')) return;
        
        this.showToast('Restoring backup...', 'info');
        
        setTimeout(() => {
            this.showToast('Backup restored!', 'success');
            this.logAction('backup_restored');
        }, 2000);
    }

    // ============================================
    // EVENT LISTENERS
    // ============================================
    setupEventListeners() {
        // Close modals on overlay click
        document.querySelectorAll('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) {
                    overlay.classList.remove('active');
                }
            });
        });

        // Close on Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal-overlay.active').forEach(m => {
                    m.classList.remove('active');
                });
            }
        });
    }

    // ============================================
    // UTILITIES
    // ============================================
    escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    showToast(message, type = 'info') {
        if (window.App) {
            window.App.showToast(message, type);
        } else {
            alert(message);
        }
    }

    logAction(action, details = {}) {
        if (window.Logger) {
            Logger.log(action, 'admin', details);
        }
    }

    // ============================================
    // CLEANUP
    // ============================================
    destroy() {
        this.initialized = false;
        console.log('Admin Panel destroyed');
    }
}

// ============================================
// INITIALIZE GLOBAL ADMIN PANEL INSTANCE
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname.includes('admin')) {
        window.AdminPanel = new AdminPanel();
    }
});

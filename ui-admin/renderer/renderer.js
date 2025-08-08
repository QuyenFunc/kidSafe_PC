const { ipcRenderer } = require('electron');

// Global state
let currentSection = 'dashboard';
let rules = [];
let logs = [];
let profiles = [];
let aiSuggestions = [];

// Initialize app
document.addEventListener('DOMContentLoaded', async () => {
    initializeNavigation();
    initializeEventListeners();
    await loadInitialData();
    startAutoRefresh();
});

function initializeNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.content-section');
    
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const sectionName = item.getAttribute('data-section');
            
            // Update active nav item
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');
            
            // Update active section
            sections.forEach(section => section.classList.remove('active'));
            document.getElementById(sectionName).classList.add('active');
            
            // Update page title
            document.getElementById('page-title').textContent = 
                item.textContent.trim();
            
            currentSection = sectionName;
            loadSectionData(sectionName);
        });
    });
}

function initializeEventListeners() {
    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', () => {
        loadSectionData(currentSection);
    });
    
    // System configuration buttons
    document.getElementById('auto-configure-btn').addEventListener('click', handleAutoConfigureSystem);
    document.getElementById('restore-system-btn').addEventListener('click', handleRestoreSystem);
    document.getElementById('check-status-btn').addEventListener('click', loadSystemStatus);

    // Individual fix buttons
    document.getElementById('fix-dns-btn').addEventListener('click', handleAutoConfigureSystem);
    document.getElementById('fix-doh-btn').addEventListener('click', handleAutoConfigureSystem);
    document.getElementById('fix-firewall-btn').addEventListener('click', handleAutoConfigureSystem);

    // Add rule button
    document.getElementById('add-rule-btn').addEventListener('click', () => {
        showModal('add-rule-modal');
    });
    
    // Add rule form
    document.getElementById('add-rule-form').addEventListener('submit', handleAddRule);
    
    // AI suggestion button
    document.getElementById('generate-suggestions').addEventListener('click', handleGenerateSuggestions);
    
    // Add selected AI rules
    document.getElementById('add-selected-rules').addEventListener('click', handleAddSelectedRules);
    
    // Modal close handlers
    document.querySelectorAll('.close, .modal-close').forEach(element => {
        element.addEventListener('click', closeModals);
    });
    
    // Settings save
    document.getElementById('save-settings').addEventListener('click', handleSaveSettings);
    
    // Log filter
    document.getElementById('log-filter').addEventListener('change', filterLogs);
}

// System configuration handlers
async function handleAutoConfigureSystem() {
    try {
        const button = document.getElementById('auto-configure-btn');
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Configuring...';
        
        await apiCall('POST', '/system/configure');
        showNotification('System configured successfully! Please restart browsers.', 'success');
        
        // Reload status after 2 seconds
        setTimeout(loadSystemStatus, 2000);
        
    } catch (error) {
        showNotification('Failed to configure system: ' + error.message, 'error');
    } finally {
        const button = document.getElementById('auto-configure-btn');
        button.disabled = false;
        button.innerHTML = '<i class="fas fa-magic"></i> Auto Configure System';
    }
}

async function handleRestoreSystem() {
    if (!confirm('This will restore original DNS and firewall settings. Continue?')) {
        return;
    }
    
    try {
        await apiCall('POST', '/system/restore');
        showNotification('System settings restored to original state', 'success');
        setTimeout(loadSystemStatus, 2000);
    } catch (error) {
        showNotification('Failed to restore system: ' + error.message, 'error');
    }
}

async function loadInitialData() {
    await Promise.all([
        loadStats(),
        loadRules(),
        loadLogs(),
        loadProfiles()
    ]);
}

async function loadSectionData(section) {
    switch (section) {
        case 'dashboard':
            await loadStats();
            break;
        case 'rules':
            await loadRules();
            break;
        case 'logs':
            await loadLogs();
            break;
        case 'profiles':
            await loadProfiles();
            break;
        case 'system-status':  // Thêm case mới
            await loadSystemStatus();
            break;
    }
}

// API calls
async function apiCall(method, endpoint, data = null) {
    try {
        const result = await ipcRenderer.invoke('api-call', method, endpoint, data);
        if (!result.success) {
            throw new Error(result.error);
        }
        return result.data;
    } catch (error) {
        console.error('API call failed:', error);
        showNotification('API Error: ' + error.message, 'error');
        throw error;
    }
}

async function loadSystemStatus() {
    try {
        const status = await apiCall('GET', '/system/status');
        updateSystemStatusUI(status);
    } catch (error) {
        console.error('Failed to load system status:', error);
    }
}

function updateSystemStatusUI(status) {
    // Update DNS status
    const dnsCard = document.getElementById('dns-status');
    const dnsText = document.getElementById('dns-status-text');
    const fixDnsBtn = document.getElementById('fix-dns-btn');
    
    if (status.dns_configured) {
        dnsCard.classList.add('status-ok');
        dnsCard.classList.remove('status-error');
        dnsText.textContent = 'Configured correctly (127.0.0.1)';
        fixDnsBtn.style.display = 'none';
    } else {
        dnsCard.classList.add('status-error');
        dnsCard.classList.remove('status-ok');
        dnsText.textContent = 'Not configured - DNS may bypass filtering';
        fixDnsBtn.style.display = 'inline-block';
    }
    
    // Update DoH status
    const dohCard = document.getElementById('doh-status');
    const dohText = document.getElementById('doh-status-text');
    const fixDohBtn = document.getElementById('fix-doh-btn');
    
    if (status.doh_disabled) {
        dohCard.classList.add('status-ok');
        dohCard.classList.remove('status-error');
        dohText.textContent = 'Disabled in browsers';
        fixDohBtn.style.display = 'none';
    } else {
        dohCard.classList.add('status-error');
        dohCard.classList.remove('status-ok');
        dohText.textContent = 'May be enabled - can bypass DNS filtering';
        fixDohBtn.style.display = 'inline-block';
    }
    
    // Update Firewall status
    const firewallCard = document.getElementById('firewall-status');
    const firewallText = document.getElementById('firewall-status-text');
    const fixFirewallBtn = document.getElementById('fix-firewall-btn');
    
    if (status.firewall_configured) {
        firewallCard.classList.add('status-ok');
        firewallCard.classList.remove('status-error');
        firewallText.textContent = 'Rules configured correctly';
        fixFirewallBtn.style.display = 'none';
    } else {
        firewallCard.classList.add('status-error');
        firewallCard.classList.remove('status-ok');
        firewallText.textContent = 'Rules not configured';
        fixFirewallBtn.style.display = 'inline-block';
    }
    
    // Show overall status notification
    if (status.overall_status) {
        showNotification('System is properly configured for parental control!', 'success');
    } else {
        showNotification('System configuration needs attention', 'warning');
    }
}

// Data loading functions
async function loadStats() {
    try {
        const stats = await apiCall('GET', '/stats');
        
        document.getElementById('total-rules').textContent = stats.total_rules || 0;
        document.getElementById('blocked-today').textContent = stats.blocked_today || 0;
        
        // Update top blocked domains
        const topBlockedList = document.getElementById('top-blocked-list');
        topBlockedList.innerHTML = '';
        
        if (stats.top_blocked && stats.top_blocked.length > 0) {
            stats.top_blocked.forEach(item => {
                const div = document.createElement('div');
                div.className = 'blocked-item';
                div.innerHTML = `
                    <span class="blocked-domain">${item.domain}</span>
                    <span class="blocked-count">${item.count}</span>
                `;
                topBlockedList.appendChild(div);
            });
        } else {
            topBlockedList.innerHTML = '<p>No blocked domains in the last 7 days</p>';
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

async function loadRules() {
    try {
        rules = await apiCall('GET', '/rules');
        renderRulesTable();
    } catch (error) {
        console.error('Failed to load rules:', error);
    }
}

async function loadLogs() {
    try {
        logs = await apiCall('GET', '/logs');
        renderLogsTable();
    } catch (error) {
        console.error('Failed to load logs:', error);
    }
}

async function loadProfiles() {
    try {
        profiles = await apiCall('GET', '/profiles');
        renderProfiles();
    } catch (error) {
        console.error('Failed to load profiles:', error);
    }
}

// Rendering functions
function renderRulesTable() {
    const tbody = document.querySelector('#rules-table tbody');
    tbody.innerHTML = '';
    
    rules.forEach(rule => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${rule.domain}</td>
            <td><span class="category-badge category-${rule.category}">${rule.category}</span></td>
            <td>${rule.reason || 'No reason provided'}</td>
            <td>${new Date(rule.created_at).toLocaleDateString()}</td>
            <td>
                <button class="btn btn-danger btn-sm" onclick="deleteRule(${rule.id})">
                    <i class="fas fa-trash"></i>
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function renderLogsTable(filteredLogs = null) {
    const tbody = document.querySelector('#logs-table tbody');
    tbody.innerHTML = '';
    
    const logsToRender = filteredLogs || logs;
    
    logsToRender.forEach(log => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date(log.timestamp).toLocaleString()}</td>
            <td>${log.domain}</td>
            <td>${log.client_ip}</td>
            <td>${log.query_type}</td>
            <td><span class="action-${log.action}">${log.action}</span></td>
        `;
        tbody.appendChild(row);
    });
}

function renderProfiles() {
    const container = document.querySelector('.profiles-grid');
    container.innerHTML = '';
    
    profiles.forEach(profile => {
        const div = document.createElement('div');
        div.className = 'profile-card';
        div.innerHTML = `
            <h3>${profile.name}</h3>
            <p>${profile.description}</p>
            <div class="profile-actions">
                <button class="btn btn-primary btn-sm">Edit</button>
                <button class="btn btn-danger btn-sm">Delete</button>
            </div>
        `;
        container.appendChild(div);
    });
}

// Event handlers
async function handleAddRule(e) {
    e.preventDefault();
    
    const domain = document.getElementById('rule-domain').value;
    const category = document.getElementById('rule-category').value;
    const reason = document.getElementById('rule-reason').value;
    
    try {
        await apiCall('POST', '/rules', {
            domain: domain,
            category: category,
            reason: reason,
            profile_id: 1
        });
        
        showNotification('Rule added successfully!', 'success');
        closeModals();
        await loadRules();
        document.getElementById('add-rule-form').reset();
    } catch (error) {
        showNotification('Failed to add rule: ' + error.message, 'error');
    }
}

async function deleteRule(id) {
    if (!confirm('Are you sure you want to delete this rule?')) {
        return;
    }
    
    try {
        await apiCall('DELETE', `/rules/${id}`);
        showNotification('Rule deleted successfully!', 'success');
        await loadRules();
    } catch (error) {
        showNotification('Failed to delete rule: ' + error.message, 'error');
    }
}

async function handleGenerateSuggestions() {
    const topic = document.getElementById('ai-topic').value;
    const category = document.getElementById('ai-category').value;
    
    if (!topic.trim()) {
        showNotification('Please enter a topic', 'error');
        return;
    }
    
    try {
        const button = document.getElementById('generate-suggestions');
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
        
        const result = await apiCall('POST', '/ai/suggest', {
            topic: topic,
            category: category
        });
        
        aiSuggestions = result.suggestions;
        renderAISuggestions();
        
        document.getElementById('ai-results').style.display = 'block';
        showNotification('AI suggestions generated!', 'success');
        
    } catch (error) {
        showNotification('Failed to generate suggestions: ' + error.message, 'error');
    } finally {
        const button = document.getElementById('generate-suggestions');
        button.disabled = false;
        button.innerHTML = '<i class="fas fa-magic"></i> Generate Suggestions';
    }
}

function renderAISuggestions() {
    const container = document.getElementById('suggestions-list');
    container.innerHTML = '';
    
    aiSuggestions.forEach((suggestion, index) => {
        const div = document.createElement('div');
        div.className = 'suggestion-item';
        div.innerHTML = `
            <div>
                <input type="checkbox" id="suggestion-${index}" data-index="${index}">
                <label for="suggestion-${index}">
                    <strong>${suggestion.domain}</strong> - ${suggestion.reason}
                </label>
            </div>
        `;
        container.appendChild(div);
    });
}

async function handleAddSelectedRules() {
    const checkboxes = document.querySelectorAll('#suggestions-list input[type="checkbox"]:checked');
    
    if (checkboxes.length === 0) {
        showNotification('Please select at least one suggestion', 'error');
        return;
    }
    
    try {
        for (const checkbox of checkboxes) {
            const index = parseInt(checkbox.getAttribute('data-index'));
            const suggestion = aiSuggestions[index];
            
            await apiCall('POST', '/rules', {
                domain: suggestion.domain,
                category: suggestion.category,
                reason: suggestion.reason,
                profile_id: 1
            });
        }
        
        showNotification(`Added ${checkboxes.length} rules successfully!`, 'success');
        await loadRules();
        document.getElementById('ai-results').style.display = 'none';
        document.getElementById('ai-topic').value = '';
        
    } catch (error) {
        showNotification('Failed to add some rules: ' + error.message, 'error');
    }
}

async function handleSaveSettings() {
    // Implementation for saving settings
    showNotification('Settings saved successfully!', 'success');
}

function filterLogs() {
    const filter = document.getElementById('log-filter').value;
    
    if (filter === 'all') {
        renderLogsTable();
    } else {
        const filtered = logs.filter(log => log.action === filter);
        renderLogsTable(filtered);
    }
}

// Utility functions
function showModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
}

function closeModals() {
    document.querySelectorAll('.modal').forEach(modal => {
        modal.style.display = 'none';
    });
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Add styles
    Object.assign(notification.style, {
        position: 'fixed',
        top: '20px',
        right: '20px',
        padding: '12px 20px',
        borderRadius: '8px',
        color: 'white',
        backgroundColor: type === 'success' ? '#34c759' : 
                        type === 'error' ? '#ff3b30' : '#007aff',
        zIndex: '10000',
        boxShadow: '0 4px 12px rgba(0,0,0,0.2)'
    });
    
    document.body.appendChild(notification);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 3000);
}

function startAutoRefresh() {
    // Auto refresh every 30 seconds
    setInterval(() => {
        if (currentSection === 'dashboard') {
            loadStats();
        } else if (currentSection === 'logs') {
            loadLogs();
        }
    }, 30000);
}

// Make functions globally available
window.deleteRule = deleteRule;

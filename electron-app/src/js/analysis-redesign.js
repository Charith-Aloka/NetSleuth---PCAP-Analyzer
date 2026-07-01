/**
 * PCAP Analyzer - Redesigned Analysis Page
 * Clean, modern implementation with pagination support
 */

// Global state
const state = {
    currentFileId: null,
    pagination: {
        ips: { page: 0, total: 0, hasMore: false },
        devices: { page: 0, total: 0, hasMore: false },
        domains: { page: 0, total: 0, hasMore: false },
        user_activity: { page: 0, total: 0, hasMore: false },
        assessments: { page: 0, total: 0, hasMore: false }
    }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadFiles();
    setupEventListeners();
    
    // Check if a file was pre-selected from the files page
    const preselectedFileId = sessionStorage.getItem('selectedFileId');
    if (preselectedFileId) {
        sessionStorage.removeItem('selectedFileId');
        
        // Wait for files to load, then auto-select and analyze
        setTimeout(() => {
            const fileSelect = document.getElementById('fileSelect');
            if (fileSelect) {
                fileSelect.value = preselectedFileId;
                state.currentFileId = parseInt(preselectedFileId);
                enableButtons();
                
                // Auto-start analysis
                startAnalysis();
            }
        }, 500);
    }
});

// Setup event listeners
function setupEventListeners() {
    const fileSelect = document.getElementById('fileSelect');
    if (fileSelect) {
        fileSelect.addEventListener('change', handleFileSelection);
    }
}

// Load available PCAP files
async function loadFiles() {
    try {
        const files = await window.api.getFiles();
        const fileSelect = document.getElementById('fileSelect');
        
        if (!fileSelect) return;
        
        if (!files || files.length === 0) {
            fileSelect.innerHTML = '<option value="">No files available</option>';
            return;
        }
        
        fileSelect.innerHTML = '<option value="">Select a file...</option>' +
            files.map(file => 
                `<option value="${file.id}">${file.filename} (${formatBytes(file.size)})</option>`
            ).join('');
            
    } catch (error) {
        console.error('Error loading files:', error);
        showToast('Failed to load files', 'error');
    }
}

// Handle file selection
function handleFileSelection(event) {
    const fileId = parseInt(event.target.value);
    
    if (!fileId) {
        disableButtons();
        hideSections();
        return;
    }
    
    state.currentFileId = fileId;
    enableButtons();
    
    showToast('File selected. Click "Analyze" to start.', 'info');
}

// Enable/disable buttons
function enableButtons() {
    document.getElementById('analyzeBtn').disabled = false;
    document.getElementById('assessBtn').disabled = false;
}

function disableButtons() {
    document.getElementById('analyzeBtn').disabled = true;
    document.getElementById('assessBtn').disabled = true;
}

// Show/hide sections
function showSections() {
    document.getElementById('summarySection').style.display = 'block';
    document.getElementById('tablesSection').style.display = 'block';
}

function hideSections() {
    document.getElementById('summarySection').style.display = 'none';
    document.getElementById('tablesSection').style.display = 'none';
}

// Start analysis
async function startAnalysis() {
    if (!state.currentFileId) {
        showToast('Please select a file first', 'warning');
        return;
    }
    
    showLoading('Analyzing PCAP file...');
    
    try {
        // Trigger analysis
        await window.api.post(`/analyze/${state.currentFileId}`, {});
        
        // Load summary
        await loadSummary();
        
        // Load initial page of each table
        await Promise.all([
            loadIPs(0),
            loadDevices(0),
            loadDomains(0),
            loadUserActivity(0)
        ]);
        
        // Check for existing assessments
        await checkAssessments();
        
        showSections();
        hideLoading();
        showToast('Analysis completed successfully!', 'success');
        
    } catch (error) {
        console.error('Analysis error:', error);
        hideLoading();
        showToast('Analysis failed: ' + (error.message || 'Unknown error'), 'error');
    }
}

// Load summary data
async function loadSummary() {
    try {
        const data = await window.api.get(`/analysis/${state.currentFileId}/summary`);
        
        if (!data.success) {
            throw new Error('Failed to load summary');
        }
        
        const counts = data.counts || {};
        const protocols = data.protocols || {};
        
        // Update summary cards
        document.getElementById('uniqueIPs').textContent = counts.ips || 0;
        document.getElementById('uniqueWebsites').textContent = counts.unique_websites || 0;
        document.getElementById('uniqueDevices').textContent = counts.devices || 0;
        document.getElementById('totalPackets').textContent = (counts.total_packets || 0).toLocaleString();
        document.getElementById('totalBytes').textContent = formatBytes(counts.total_bytes || 0);
        document.getElementById('analyzedAt').textContent = data.analyzed_at 
            ? new Date(data.analyzed_at).toLocaleString() 
            : 'Just now';
        
        // Animate count-up effect
        animateValue('uniqueIPs', 0, counts.ips || 0, 1000);
        animateValue('uniqueWebsites', 0, counts.unique_websites || 0, 1000);
        animateValue('uniqueDevices', 0, counts.devices || 0, 1000);
        
    } catch (error) {
        console.error('Error loading summary:', error);
        throw error;
    }
}

// Load IPs
async function loadIPs(page) {
    try {
        const data = await window.api.get(`/analysis/${state.currentFileId}/ips`, { page, limit: 10 });
        
        if (!data.success) {
            throw new Error('Failed to load IPs');
        }
        
        const tbody = document.getElementById('ipsTableBody');
        const items = data.items || [];
        
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" class="text-center">No IP addresses found</td></tr>';
        } else {
            tbody.innerHTML = items.map(item => `
                <tr>
                    <td>${escapeHtml(item.ip)}</td>
                    <td>${(item.count || 0).toLocaleString()}</td>
                </tr>
            `).join('');
        }
        
        // Update pagination
        updatePagination('ips', data.pagination);
        
    } catch (error) {
        console.error('Error loading IPs:', error);
        document.getElementById('ipsTableBody').innerHTML = 
            '<tr><td colspan="2" class="text-center">Error loading data</td></tr>';
    }
}

// Load Devices
async function loadDevices(page) {
    try {
        const data = await window.api.get(`/analysis/${state.currentFileId}/devices`, { page, limit: 10 });
        
        if (!data.success) {
            throw new Error('Failed to load devices');
        }
        
        const tbody = document.getElementById('devicesTableBody');
        const items = data.items || [];
        
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No devices found</td></tr>';
        } else {
            tbody.innerHTML = items.map(item => `
                <tr>
                    <td>${escapeHtml(item.ip || '-')}</td>
                    <td>${escapeHtml(item.mac || '-')}</td>
                    <td>${escapeHtml(item.hostname || '-')}</td>
                    <td>${formatTimestamp(item.first_seen)}</td>
                    <td>${formatTimestamp(item.last_seen)}</td>
                </tr>
            `).join('');
        }
        
        // Update pagination
        updatePagination('devices', data.pagination);
        
    } catch (error) {
        console.error('Error loading devices:', error);
        document.getElementById('devicesTableBody').innerHTML = 
            '<tr><td colspan="5" class="text-center">Error loading data</td></tr>';
    }
}

// Load Domains
async function loadDomains(page) {
    try {
        const data = await window.api.get(`/analysis/${state.currentFileId}/domains`, { page, limit: 10 });
        
        if (!data.success) {
            throw new Error('Failed to load domains');
        }
        
        const tbody = document.getElementById('domainsTableBody');
        const items = data.items || [];
        
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center">No domains found</td></tr>';
        } else {
            tbody.innerHTML = items.map(item => `
                <tr>
                    <td>${escapeHtml(item.ip || '-')}</td>
                    <td>${escapeHtml(item.domain || '-')}</td>
                    <td>${escapeHtml(item.source || '-')}</td>
                    <td>${(item.count || 0).toLocaleString()}</td>
                </tr>
            `).join('');
        }
        
        // Update pagination
        updatePagination('domains', data.pagination);
        
    } catch (error) {
        console.error('Error loading domains:', error);
        document.getElementById('domainsTableBody').innerHTML = 
            '<tr><td colspan="4" class="text-center">Error loading data</td></tr>';
    }
}

// Load User Activity
async function loadUserActivity(page) {
    try {
        const data = await window.api.get(`/analysis/${state.currentFileId}/user_activity`, { page, limit: 10 });
        
        if (!data.success) {
            throw new Error('Failed to load user activity');
        }
        
        const tbody = document.getElementById('userActivityTableBody');
        const items = data.items || [];
        
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No user activity found</td></tr>';
        } else {
            tbody.innerHTML = items.map(item => {
                const domains = (item.domains || []).slice(0, 3).join(', ');
                const moreCount = (item.domains || []).length - 3;
                const domainsText = domains + (moreCount > 0 ? ` (+${moreCount} more)` : '');
                
                const timeRange = item.time_start && item.time_end
                    ? `${formatTimestamp(item.time_start)} - ${formatTimestamp(item.time_end)}`
                    : '-';
                
                return `
                    <tr>
                        <td>${escapeHtml(item.ip)}</td>
                        <td>${escapeHtml(item.mac || '-')}</td>
                        <td>${escapeHtml(item.hostname || '-')}</td>
                        <td><small>${escapeHtml(domainsText || '-')}</small></td>
                        <td><small>${timeRange}</small></td>
                    </tr>
                `;
            }).join('');
        }
        
        // Update pagination
        updatePagination('user_activity', data.pagination);
        
    } catch (error) {
        console.error('Error loading user activity:', error);
        document.getElementById('userActivityTableBody').innerHTML = 
            '<tr><td colspan="5" class="text-center">Error loading data</td></tr>';
    }
}

// Check for existing assessments
async function checkAssessments() {
    try {
        const data = await window.api.get(`/analysis/${state.currentFileId}/assessments`, { summary: 'true' });
        
        if (data.available && data.total > 0) {
            // Load assessments
            await loadAssessments(0);
            
            // Update threat count in summary
            document.getElementById('threatCount').textContent = data.threats_found || 0;
        } else {
            // Show empty state
            document.getElementById('threatEmptyState').style.display = 'block';
            document.getElementById('assessmentsTableContainer').style.display = 'none';
            document.getElementById('assessmentsPagination').style.display = 'none';
        }
        
    } catch (error) {
        console.error('Error checking assessments:', error);
    }
}

// Load Assessments
async function loadAssessments(page) {
    try {
        const data = await window.api.get(`/analysis/${state.currentFileId}/assessments`, { page, limit: 10 });
        
        if (!data.success) {
            throw new Error('Failed to load assessments');
        }
        
        const tbody = document.getElementById('assessmentsTableBody');
        const items = data.items || [];
        
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center">No assessments found</td></tr>';
        } else {
            tbody.innerHTML = items.map(item => {
                const verdictClass = getVerdictClass(item.verdict);
                const reasons = Array.isArray(item.reasons) ? item.reasons.join('; ') : (item.reasons || '-');
                
                return `
                    <tr>
                        <td>${escapeHtml(item.domain)}</td>
                        <td><span class="verdict-badge ${verdictClass}">${escapeHtml(item.verdict)}</span></td>
                        <td><small>${escapeHtml(reasons)}</small></td>
                        <td><small>${formatTimestamp(item.assessed_at)}</small></td>
                    </tr>
                `;
            }).join('');
            
            // Show table and pagination
            document.getElementById('threatEmptyState').style.display = 'none';
            document.getElementById('assessmentsTableContainer').style.display = 'block';
            document.getElementById('assessmentsPagination').style.display = 'flex';
        }
        
        // Update pagination
        updatePagination('assessments', data.pagination);
        
    } catch (error) {
        console.error('Error loading assessments:', error);
        document.getElementById('assessmentsTableBody').innerHTML = 
            '<tr><td colspan="4" class="text-center">Error loading data</td></tr>';
    }
}

// Assess threats
async function assessThreats() {
    if (!state.currentFileId) {
        showToast('Please select and analyze a file first', 'warning');
        return;
    }
    
    showLoading('Running threat assessment with Gemini AI...');
    
    try {
        const result = await window.api.assessDomains(state.currentFileId);
        
        if (!result.success) {
            throw new Error(result.error || 'Assessment failed');
        }
        
        // Load assessments
        await loadAssessments(0);
        
        // Update summary
        const summary = await window.api.get(`/analysis/${state.currentFileId}/assessments`, { summary: 'true' });
        document.getElementById('threatCount').textContent = summary.threats_found || 0;
        
        hideLoading();
        showToast(`Assessment completed! Found ${summary.threats_found || 0} threats.`, 'success');
        
    } catch (error) {
        console.error('Assessment error:', error);
        hideLoading();
        
        const errorMsg = error.message || 'Unknown error';
        if (errorMsg.includes('timeout')) {
            showToast('Assessment timed out. The file may have too many domains. Try with a smaller file.', 'error');
        } else {
            showToast('Assessment failed: ' + errorMsg, 'error');
        }
    }
}

// Change page
function changePage(type, direction) {
    const paginationState = state.pagination[type];
    if (!paginationState) return;
    
    const newPage = paginationState.page + direction;
    
    // Validate page bounds
    if (newPage < 0) return;
    if (direction > 0 && !paginationState.hasMore) return;
    
    // Load new page
    switch (type) {
        case 'ips':
            loadIPs(newPage);
            break;
        case 'devices':
            loadDevices(newPage);
            break;
        case 'domains':
            loadDomains(newPage);
            break;
        case 'user_activity':
            loadUserActivity(newPage);
            break;
        case 'assessments':
            loadAssessments(newPage);
            break;
    }
}

// Update pagination UI
function updatePagination(type, paginationData) {
    if (!paginationData) return;
    
    // Update state
    state.pagination[type] = {
        page: paginationData.page,
        total: paginationData.total,
        hasMore: paginationData.has_more
    };
    
    const { page, total, hasMore } = state.pagination[type];
    const limit = paginationData.limit || 10;
    const totalPages = Math.ceil(total / limit);
    const currentPage = page + 1;
    
    // Update badge
    const badge = document.getElementById(`${type}Badge`);
    if (badge) {
        badge.textContent = total;
    }
    
    // Update page info
    const pageInfo = document.getElementById(`${type}PageInfo`);
    if (pageInfo) {
        pageInfo.textContent = `Page ${currentPage} of ${totalPages || 1}`;
    }
    
    // Update buttons
    const prevBtn = document.getElementById(`${type}Prev`);
    const nextBtn = document.getElementById(`${type}Next`);
    
    if (prevBtn) {
        prevBtn.disabled = page === 0;
    }
    
    if (nextBtn) {
        nextBtn.disabled = !hasMore;
    }
}

// Utility functions
function showLoading(message) {
    const overlay = document.getElementById('loadingOverlay');
    const messageEl = document.getElementById('loadingMessage');
    
    if (overlay) overlay.style.display = 'flex';
    if (messageEl) messageEl.textContent = message || 'Loading...';
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.style.display = 'none';
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icon = getToastIcon(type);
    
    toast.innerHTML = `
        <i class="fas ${icon}"></i>
        <span class="toast-message">${escapeHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    container.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }
    }, 5000);
}

function getToastIcon(type) {
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    return icons[type] || icons.info;
}

function getVerdictClass(verdict) {
    const classes = {
        malicious: 'verdict-malicious',
        suspicious: 'verdict-suspicious',
        benign: 'verdict-benign'
    };
    return classes[verdict?.toLowerCase()] || 'verdict-unknown';
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatTimestamp(timestamp) {
    if (!timestamp) return '-';
    try {
        const date = new Date(timestamp * 1000); // Assuming Unix timestamp
        if (isNaN(date.getTime())) {
            return new Date(timestamp).toLocaleString(); // Try ISO format
        }
        return date.toLocaleString();
    } catch {
        return '-';
    }
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = text.toString();
    return div.innerHTML;
}

function animateValue(elementId, start, end, duration) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const range = end - start;
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const value = Math.floor(start + range * progress);
        element.textContent = value.toLocaleString();
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

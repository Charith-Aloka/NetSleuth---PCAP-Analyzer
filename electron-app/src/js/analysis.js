// Analysis Management System

class AnalysisManager {
    constructor() {
        this.currentFileId = null;
        this.analysisData = null;
        this.initialized = false;
    }

    init() {
        if (this.initialized) return;
        this.initialized = true;
        console.log('Analysis Manager initialized');
    }

    // Trigger analysis for selected file
    async triggerAnalysis() {
        const analysisFileSelect = window.ui.get('analysisFileSelect');
        if (!analysisFileSelect || !analysisFileSelect.value) {
            window.ui.showStatus('Please select a PCAP file to analyze', 'warning');
            return;
        }

        const fileId = analysisFileSelect.value;
        
        try {
            window.ui.showLoading();
            window.ui.showStatus('Starting analysis...', 'info');
            
            console.log(`Starting analysis for file ID: ${fileId}`);
            
            // Trigger analysis on backend
            const result = await window.api.post(`/analyze/${fileId}`);
            
            window.ui.showStatus('Analysis completed successfully!', 'success');
            
            // Refresh the analysis results
            await this.refreshAnalysis();
            
        } catch (error) {
            console.error('Analysis error:', error);
            window.ui.showStatus(`Analysis failed: ${error.message}`, 'error');
        } finally {
            window.ui.hideLoading();
        }
    }

    // Refresh analysis results display
    async refreshAnalysis() {
        const analysisFileSelect = window.ui.get('analysisFileSelect');
        if (!analysisFileSelect || !analysisFileSelect.value) {
            this.clearAnalysisDisplay();
            return;
        }

        const fileId = analysisFileSelect.value;
        this.currentFileId = fileId;

        try {
            console.log(`Refreshing analysis for file ID: ${fileId}`);
            
            // Load analysis summary
            const summary = await window.api.get(`/analysis/${fileId}/summary`);
            this.updateSummaryDisplay(summary);

            // Load detailed analysis data
            await this.loadAnalysisData(fileId);
            
        } catch (error) {
            console.error('Error refreshing analysis:', error);
            
            // If analysis doesn't exist yet, show zeros
            if (error.status === 404 || error.message.includes('not found')) {
                this.clearAnalysisDisplay();
            } else {
                window.ui.showStatus(`Error loading analysis: ${error.message}`, 'error');
            }
        }
    }

    // Update summary display
    updateSummaryDisplay(summary) {
        const elements = {
            sumIPs: window.ui.get('sumIPs'),
            sumDevices: window.ui.get('sumDevices'),
            sumDomains: window.ui.get('sumDomains'),
            sumFlows: window.ui.get('sumFlows'),
            sumAnalyzedAt: window.ui.get('sumAnalyzedAt')
        };

        if (elements.sumIPs) elements.sumIPs.textContent = summary.counts?.ips || 0;
        if (elements.sumDevices) elements.sumDevices.textContent = summary.counts?.devices || 0;
        if (elements.sumDomains) elements.sumDomains.textContent = summary.counts?.domains || 0;
        if (elements.sumFlows) elements.sumFlows.textContent = summary.counts?.flows || 0;
        
        if (elements.sumAnalyzedAt) {
            elements.sumAnalyzedAt.textContent = summary.analyzed_at ? 
                this.formatTimestamp(summary.analyzed_at) : '-';
        }
    }

    // Load and display detailed analysis data
    async loadAnalysisData(fileId) {
        try {
            // Load all analysis data in parallel
            const [ips, devices, domains, flows] = await Promise.all([
                window.api.get(`/analysis/${fileId}/ips`),
                window.api.get(`/analysis/${fileId}/devices`),
                window.api.get(`/analysis/${fileId}/domains`),
                window.api.get(`/analysis/${fileId}/flows`)
            ]);

            // Render tables
            this.renderIPsTable(ips.items || []);
            this.renderDevicesTable(devices.items || []);
            this.renderDomainsTable(domains.items || []);
            this.renderFlowsTable(flows.items || []);

        } catch (error) {
            console.error('Error loading analysis data:', error);
            this.clearAnalysisTables();
        }
    }

    // Render IP addresses table
    renderIPsTable(ips) {
        const tbody = document.querySelector('#ipsTable tbody');
        if (!tbody) return;

        if (ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-muted);">No IP data available</td></tr>';
            return;
        }

        tbody.innerHTML = ips.map(ip => `
            <tr>
                <td>${this.escapeHtml(ip.ip)}</td>
                <td>${ip.count}</td>
            </tr>
        `).join('');
    }

    // Render devices table
    renderDevicesTable(devices) {
        const tbody = document.querySelector('#devicesTable tbody');
        if (!tbody) return;

        if (devices.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No device data available</td></tr>';
            return;
        }

        tbody.innerHTML = devices.map(device => `
            <tr>
                <td>${this.escapeHtml(device.ip)}</td>
                <td>${device.mac || '-'}</td>
                <td>${device.hostname || '-'}</td>
                <td>${this.formatTimestamp(device.first_seen)}</td>
                <td>${this.formatTimestamp(device.last_seen)}</td>
            </tr>
        `).join('');
    }

    // Render domains table
    renderDomainsTable(domains) {
        const tbody = document.querySelector('#domainsTable tbody');
        if (!tbody) return;

        if (domains.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No domain data available</td></tr>';
            return;
        }

        tbody.innerHTML = domains.map(domain => `
            <tr>
                <td>${domain.ip || '-'}</td>
                <td>${this.escapeHtml(domain.domain)}</td>
                <td>${domain.source || '-'}</td>
                <td>${domain.count}</td>
            </tr>
        `).join('');
    }

    // Render flows table
    renderFlowsTable(flows) {
        const tbody = document.querySelector('#flowsTable tbody');
        if (!tbody) return;

        if (flows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No flow data available</td></tr>';
            return;
        }

        tbody.innerHTML = flows.map(flow => `
            <tr>
                <td>${this.escapeHtml(flow.src_ip)}</td>
                <td>${flow.src_port || '-'}</td>
                <td>${this.escapeHtml(flow.dst_ip)}</td>
                <td>${flow.dst_port || '-'}</td>
                <td>${flow.protocol || '-'}</td>
                <td>${flow.packet_count}</td>
                <td>${this.formatBytes(flow.byte_count)}</td>
                <td>${this.formatTimestamp(flow.first_seen)}</td>
                <td>${this.formatTimestamp(flow.last_seen)}</td>
            </tr>
        `).join('');
    }

    // Clear analysis display
    clearAnalysisDisplay() {
        // Clear summary
        const summaryElements = ['sumIPs', 'sumDevices', 'sumDomains', 'sumFlows', 'sumAnalyzedAt'];
        summaryElements.forEach(elementId => {
            const element = window.ui.get(elementId);
            if (element) {
                element.textContent = elementId === 'sumAnalyzedAt' ? '-' : '0';
            }
        });

        // Clear tables
        this.clearAnalysisTables();
    }

    // Clear all analysis tables
    clearAnalysisTables() {
        const tables = ['#ipsTable tbody', '#devicesTable tbody', '#domainsTable tbody', '#flowsTable tbody'];
        tables.forEach(selector => {
            const tbody = document.querySelector(selector);
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="100%" style="text-align: center; color: var(--text-muted);">No data available</td></tr>';
            }
        });
    }

    // Utility functions
    formatTimestamp(timestamp) {
        if (!timestamp && timestamp !== 0) return '-';
        
        try {
            const date = new Date(timestamp * 1000);
            return date.toLocaleTimeString();
        } catch (error) {
            console.warn('Error formatting timestamp:', timestamp);
            return '-';
        }
    }

    formatBytes(bytes) {
        if (bytes === 0 || !bytes) return '0 B';
        
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global function for triggering analysis (for button onclick)
window.triggerAnalysis = function() {
    if (window.analysisManager) {
        window.analysisManager.triggerAnalysis();
    }
};

// Initialize Analysis Manager
window.analysisManager = new AnalysisManager();

// UI Helper Functions and Components

class UIManager {
    constructor() {
        this.elements = new Map();
        this.initialized = false;
    }

    init() {
        if (this.initialized) return;

        // Cache DOM elements
        this.cacheElements();
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Initialize tabs
        this.initializeTabs();
        
        this.initialized = true;
        console.log('UI Manager initialized');
    }

    cacheElements() {
        const selectors = {
            // Navigation
            navTabs: '.nav-tab',
            tabContents: '.tab-content',
            
            // Files section
            fileInput: '#fileInput',
            uploadArea: '#uploadArea',
            filesGrid: '#filesGrid',
            emptyState: '#emptyState',
            searchInput: '#searchInput',
            sortSelect: '#sortSelect',
            
            // Analysis section
            analysisFileSelect: '#analysisFileSelect',
            
            // Progress and loading
            uploadProgress: '#uploadProgress',
            progressFill: '#progressFill',
            progressText: '#progressText',
            loadingOverlay: '#loadingOverlay',
            
            // Statistics
            totalFiles: '#totalFiles',
            totalSize: '#totalSize',
            
            // Analysis summary
            sumIPs: '#sumIPs',
            sumDevices: '#sumDevices',
            sumDomains: '#sumDomains',
            sumFlows: '#sumFlows',
            sumAnalyzedAt: '#sumAnalyzedAt',
            
            // Modals
            deleteModal: '#deleteModal',
            deleteMessage: '#deleteMessage',
            confirmDeleteBtn: '#confirmDeleteBtn',
            
            // Status container
            statusContainer: '#statusContainer'
        };

        for (const [key, selector] of Object.entries(selectors)) {
            const element = document.querySelector(selector);
            if (element) {
                this.elements.set(key, element);
            } else {
                console.warn(`Element not found: ${selector}`);
            }
        }
    }

    get(elementKey) {
        return this.elements.get(elementKey);
    }

    setupEventListeners() {
        // File input change
        const fileInput = this.get('fileInput');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                const files = Array.from(e.target.files);
                if (files.length > 0) {
                    window.fileManager.uploadFiles(files);
                }
            });
        }

        // Search functionality
        const searchInput = this.get('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', () => {
                window.fileManager.filterFiles();
            });
        }

        // Sort functionality
        const sortSelect = this.get('sortSelect');
        if (sortSelect) {
            sortSelect.addEventListener('change', () => {
                window.fileManager.sortFiles();
            });
        }

        // Analysis file select
        const analysisFileSelect = this.get('analysisFileSelect');
        if (analysisFileSelect) {
            analysisFileSelect.addEventListener('change', () => {
                window.analysisManager.refreshAnalysis();
            });
        }

        // Drag and drop for upload area
        this.setupDragAndDrop();

        // Modal close events
        this.setupModalEvents();

        // Keyboard shortcuts
        this.setupKeyboardShortcuts();
    }

    setupDragAndDrop() {
        const uploadArea = this.get('uploadArea');
        if (!uploadArea) return;

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            uploadArea.classList.add('drag-over');
        });

        uploadArea.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            uploadArea.classList.remove('drag-over');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            uploadArea.classList.remove('drag-over');
            
            const files = Array.from(e.dataTransfer.files);
            if (files.length > 0) {
                window.fileManager.uploadFiles(files);
            }
        });

        uploadArea.addEventListener('click', () => {
            const fileInput = this.get('fileInput');
            if (fileInput) fileInput.click();
        });
    }

    setupModalEvents() {
        const deleteModal = this.get('deleteModal');
        if (deleteModal) {
            deleteModal.addEventListener('click', (e) => {
                if (e.target === deleteModal) {
                    this.closeDeleteModal();
                }
            });
        }
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // ESC to close modals
            if (e.key === 'Escape') {
                this.closeDeleteModal();
            }
            
            // Ctrl+O to open file dialog
            if (e.ctrlKey && e.key === 'o') {
                e.preventDefault();
                const fileInput = this.get('fileInput');
                if (fileInput) fileInput.click();
            }
            
            // F5 to refresh
            if (e.key === 'F5') {
                e.preventDefault();
                window.fileManager.loadFiles();
            }
        });
    }

    initializeTabs() {
        const navTabs = document.querySelectorAll('.nav-tab');
        navTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.dataset.tab;
                this.switchTab(targetTab);
            });
        });
    }

    switchTab(tabName) {
        // Update nav tabs
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabName);
        });

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === tabName);
        });

        console.log(`Switched to tab: ${tabName}`);
    }

    // Progress Management
    showProgress() {
        const progressElement = this.get('uploadProgress');
        if (progressElement) {
            progressElement.style.display = 'block';
        }
    }

    hideProgress() {
        const progressElement = this.get('uploadProgress');
        if (progressElement) {
            progressElement.style.display = 'none';
        }
    }

    updateProgress(percent, text) {
        const progressFill = this.get('progressFill');
        const progressText = this.get('progressText');
        
        if (progressFill) {
            progressFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
        }
        
        if (progressText && text) {
            progressText.textContent = text;
        }
    }

    // Loading Overlay Management
    showLoading() {
        const overlay = this.get('loadingOverlay');
        if (overlay) {
            overlay.style.display = 'flex';
        }
    }

    hideLoading() {
        const overlay = this.get('loadingOverlay');
        if (overlay) {
            overlay.style.display = 'none';
        }
    }

    // Status Messages
    showStatus(message, type = 'info', duration = 5000) {
        const container = this.get('statusContainer');
        if (!container) return;

        const statusElement = document.createElement('div');
        statusElement.className = `status-message ${type}`;
        
        let icon = 'fas fa-info-circle';
        if (type === 'success') icon = 'fas fa-check-circle';
        else if (type === 'error') icon = 'fas fa-exclamation-circle';
        else if (type === 'warning') icon = 'fas fa-exclamation-triangle';
        
        statusElement.innerHTML = `
            <i class="${icon}"></i>
            <span>${message}</span>
        `;
        
        container.appendChild(statusElement);
        
        // Auto remove
        setTimeout(() => {
            if (statusElement.parentNode) {
                statusElement.parentNode.removeChild(statusElement);
            }
        }, duration);
    }

    // Modal Management
    showDeleteModal(message, onConfirm) {
        const modal = this.get('deleteModal');
        const messageElement = this.get('deleteMessage');
        const confirmBtn = this.get('confirmDeleteBtn');
        
        if (!modal || !messageElement || !confirmBtn) return;
        
        messageElement.textContent = message;
        
        // Remove previous listeners
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
        this.elements.set('confirmDeleteBtn', newConfirmBtn);
        
        newConfirmBtn.onclick = () => {
            onConfirm();
            this.closeDeleteModal();
        };
        
        modal.style.display = 'flex';
    }

    closeDeleteModal() {
        const modal = this.get('deleteModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    // Statistics Update
    updateStats(stats) {
        const totalFilesElement = this.get('totalFiles');
        const totalSizeElement = this.get('totalSize');
        
        if (totalFilesElement) {
            totalFilesElement.textContent = stats.totalFiles || 0;
        }
        
        if (totalSizeElement) {
            totalSizeElement.textContent = stats.totalSize || '0 B';
        }
    }

    // Utility Functions
    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    formatDate(isoString) {
        const date = new Date(isoString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    truncateFilename(filename, maxLength) {
        if (filename.length <= maxLength) return filename;
        
        const ext = filename.split('.').pop() || '';
        const nameWithoutExt = filename.substring(0, filename.lastIndexOf('.'));
        const truncated = nameWithoutExt.substring(0, maxLength - ext.length - 4) + '...';
        
        return truncated + '.' + ext;
    }
}

// Global functions for backward compatibility
window.confirmDeleteAll = function() {
    if (window.fileManager && window.fileManager.filesData.length === 0) {
        window.ui.showStatus('No files to delete', 'info');
        return;
    }
    
    const count = window.fileManager ? window.fileManager.filesData.length : 0;
    window.ui.showDeleteModal(
        `Are you sure you want to delete all ${count} files? This action cannot be undone.`,
        () => window.fileManager.deleteAllFiles()
    );
};

window.closeDeleteModal = function() {
    window.ui.closeDeleteModal();
};

window.sortFiles = function() {
    if (window.fileManager) {
        window.fileManager.sortFiles();
    }
};

// Initialize UI Manager
window.ui = new UIManager();

// File Management System

class FileManager {
    constructor() {
        this.filesData = [];
        this.filteredFiles = [];
        this.initialized = false;
    }

    init() {
        if (this.initialized) return;
        this.initialized = true;
        console.log('File Manager initialized');
    }

    // Load files from backend
    async loadFiles() {
        try {
            console.log('Loading files from backend...');
            window.ui.showLoading();
            
            // Clear existing data before loading new data to prevent memory accumulation
            this.filesData = [];
            this.filteredFiles = [];
            
            const data = await window.api.get('/files');
            this.filesData = data.files || [];
            
            // Use slice instead of spread operator for better performance with large arrays
            this.filteredFiles = this.filesData.slice();
            
            console.log(`Loaded ${this.filesData.length} files`);
            
            // Use requestAnimationFrame to prevent UI blocking
            requestAnimationFrame(() => {
                this.renderFiles();
                this.updateStatistics();
            });
            
        } catch (error) {
            console.error('Error loading files:', error);
            // Ensure data is cleared even on error
            this.filesData = [];
            this.filteredFiles = [];
            this.renderFiles();
            window.ui.showStatus(`Error loading files: ${error.message}`, 'error');
        } finally {
            window.ui.hideLoading();
        }
    }

    // Upload multiple files
    async uploadFiles(files) {
        window.ui.showProgress();
        
        let successCount = 0;
        const totalFiles = files.length;
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            
            try {
                window.ui.updateProgress(
                    (i / totalFiles) * 100,
                    `Uploading ${file.name}... (${i + 1}/${totalFiles})`
                );
                
                const formData = new FormData();
                formData.append('file', file);
                
                const result = await window.api.post('/upload', formData);
                
                successCount++;
                window.ui.showStatus(`Uploaded: ${file.name}`, 'success');
                
            } catch (error) {
                console.error(`Error uploading ${file.name}:`, error);
                
                if (error.status === 409) {
                    window.ui.showStatus(`File already exists: ${file.name}`, 'info');
                } else {
                    window.ui.showStatus(`Failed to upload ${file.name}: ${error.message}`, 'error');
                }
            }
        }
        
        window.ui.updateProgress(100, `Upload complete! ${successCount}/${totalFiles} files uploaded.`);
        
        setTimeout(() => {
            window.ui.hideProgress();
            this.loadFiles();
            
            // Reset file input
            const fileInput = window.ui.get('fileInput');
            if (fileInput) fileInput.value = '';
        }, 1500);
    }

    // Render files in the grid
    renderFiles() {
        const filesGrid = window.ui.get('filesGrid');
        const emptyState = window.ui.get('emptyState');
        
        if (!filesGrid || !emptyState) return;
        
        if (!this.filteredFiles || this.filteredFiles.length === 0) {
            filesGrid.style.display = 'none';
            emptyState.style.display = 'block';
            return;
        }
        
        filesGrid.style.display = 'grid';
        emptyState.style.display = 'none';
        
        // Clear existing content to prevent memory leaks
        filesGrid.innerHTML = '';
        
        // Use DocumentFragment for efficient DOM manipulation
        const fragment = document.createDocumentFragment();
        
        this.filteredFiles.forEach(file => {
            const card = document.createElement('div');
            card.className = 'file-card';
            card.dataset.fileId = file.id;
            
            // Escape HTML to prevent XSS
            const escapedName = this.escapeHtml(file.original_filename);
            const escapedNameForJs = file.original_filename.replace(/'/g, "\\'").replace(/"/g, '\\"');
            
            card.innerHTML = `
                <div class="file-icon">
                    <i class="fas fa-file-alt"></i>
                </div>
                <div class="file-info">
                    <div class="file-name" title="${escapedName}">
                        ${window.ui.truncateFilename(escapedName, 30)}
                    </div>
                    <div class="file-meta">
                        ${file.size_formatted} • ${window.ui.formatDate(file.uploaded_at)}
                    </div>
                </div>
                <div class="file-actions">
                    <button class="btn" data-action="download" data-file-id="${file.id}" data-filename="${escapedNameForJs}">
                        <i class="fas fa-download"></i>
                        Download
                    </button>
                    <button class="btn btn-primary" data-action="analyze" data-file-id="${file.id}">
                        <i class="fas fa-microscope"></i>
                        Analyze
                    </button>
                    <button class="btn btn-danger" data-action="delete" data-file-id="${file.id}" data-filename="${escapedNameForJs}">
                        <i class="fas fa-trash"></i>
                        Delete
                    </button>
                </div>
            `;
            fragment.appendChild(card);
        });
        
        filesGrid.appendChild(fragment);
        this.attachFileEventListeners();
    }

    // Attach event listeners using delegation to prevent memory leaks
    attachFileEventListeners() {
        const filesGrid = window.ui.get('filesGrid');
        if (!filesGrid) return;
        
        // Remove existing listeners
        const existingListener = filesGrid._fileListener;
        if (existingListener) {
            filesGrid.removeEventListener('click', existingListener);
        }
        
        // Add new delegated listener
        const newListener = (e) => {
            const button = e.target.closest('button[data-action]');
            if (!button) return;
            
            // Prevent double-clicks
            if (button.disabled) return;
            
            const action = button.dataset.action;
            const fileId = button.dataset.fileId;
            const filename = button.dataset.filename;
            
            switch (action) {
                case 'download':
                    this.downloadFile(fileId, filename);
                    break;
                case 'analyze':
                    // Disable button and show loading state
                    button.disabled = true;
                    const originalHTML = button.innerHTML;
                    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
                    
                    // Store original state to restore if needed
                    button._originalHTML = originalHTML;
                    
                    this.selectAndAnalyze(fileId);
                    break;
                case 'delete':
                    this.confirmDeleteFile(fileId, filename);
                    break;
            }
        };
        
        filesGrid.addEventListener('click', newListener);
        filesGrid._fileListener = newListener;
    }

    // Utility to escape HTML
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Update analysis dropdown
    // Update statistics
    updateStatistics() {
        const totalSize = this.filesData.reduce((sum, file) => sum + file.size, 0);
        
        window.ui.updateStats({
            totalFiles: this.filesData.length,
            totalSize: window.ui.formatFileSize(totalSize)
        });
    }

    // Filter files based on search (optimized for memory efficiency)
    filterFiles() {
        const searchInput = window.ui.get('searchInput');
        if (!searchInput) return;
        
        const searchTerm = searchInput.value.toLowerCase().trim();
        
        // Avoid creating new arrays when not necessary
        if (!searchTerm) {
            if (this.filteredFiles !== this.filesData) {
                this.filteredFiles = this.filesData.slice(); // Use slice instead of spread
            }
        } else {
            // Use more efficient filtering with early termination
            this.filteredFiles = [];
            for (const file of this.filesData) {
                const filename = (file.original_filename || '').toLowerCase();
                const storedFilename = (file.filename || '').toLowerCase();
                const extension = this.getFileExtension(file.filename).toLowerCase();
                
                if (filename.includes(searchTerm) || 
                    storedFilename.includes(searchTerm) || 
                    extension.includes(searchTerm)) {
                    this.filteredFiles.push(file);
                }
            }
        }
        
        // Use requestAnimationFrame to prevent UI blocking
        requestAnimationFrame(() => this.renderFiles());
    }

    // Sort files (optimized for memory efficiency)
    sortFiles() {
        const sortSelect = window.ui.get('sortSelect');
        if (!sortSelect) return;
        
        const sortBy = sortSelect.value;
        if (!sortBy || this.filteredFiles.length === 0) return;
        
        // Sort in place instead of creating new array
        switch (sortBy) {
            case 'date-desc':
                this.filteredFiles.sort((a, b) => new Date(b.uploaded_at) - new Date(a.uploaded_at));
                break;
            case 'date-asc':
                this.filteredFiles.sort((a, b) => new Date(a.uploaded_at) - new Date(b.uploaded_at));
                break;
            case 'name-asc':
                this.filteredFiles.sort((a, b) => a.original_filename.localeCompare(b.original_filename));
                break;
            case 'name-desc':
                this.filteredFiles.sort((a, b) => b.original_filename.localeCompare(a.original_filename));
                break;
            case 'size-desc':
                this.filteredFiles.sort((a, b) => (b.size || 0) - (a.size || 0));
                break;
            case 'size-asc':
                this.filteredFiles.sort((a, b) => (a.size || 0) - (b.size || 0));
                break;
        }
        
        // Use requestAnimationFrame to prevent UI blocking
        requestAnimationFrame(() => this.renderFiles());
    }

    // Download file
    async downloadFile(fileId, filename) {
        try {
            window.ui.showStatus(`Downloading ${filename}...`, 'info');
            
            const response = await window.api.download(`/download/${fileId}`);
            
            if (response instanceof Response) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
                
                window.ui.showStatus(`Downloaded: ${filename}`, 'success');
            } else {
                throw new Error('Invalid response format');
            }
            
        } catch (error) {
            console.error('Download error:', error);
            window.ui.showStatus(`Download failed: ${error.message}`, 'error');
        }
    }

    // Delete single file
    async deleteFile(fileId) {
        try {
            const result = await window.api.delete(`/delete/${fileId}`);
            
            // Remove from local data arrays to prevent memory leaks
            this.filesData = this.filesData.filter(f => f.id !== fileId);
            this.applyFilters();
            
            window.ui.showStatus(result.message || 'File deleted successfully', 'success');
            
            // Optionally trigger garbage collection
            this.cleanupMemory();
            
        } catch (error) {
            console.error('Delete error:', error);
            window.ui.showStatus(`Delete failed: ${error.message}`, 'error');
        }
    }

    // Delete all files
    async deleteAllFiles() {
        window.ui.showLoading();
        
        let deletedCount = 0;
        for (const file of this.filesData) {
            try {
                await window.api.delete(`/delete/${file.id}`);
                deletedCount++;
            } catch (error) {
                console.error(`Error deleting file ${file.id}:`, error);
            }
        }
        
        // Clear local data arrays to prevent memory leaks
        this.filesData = [];
        this.filteredFiles = [];
        this.renderFiles();
        
        window.ui.hideLoading();
        window.ui.showStatus(`Deleted ${deletedCount} files`, 'success');
        
        // Optionally trigger garbage collection
        this.cleanupMemory();
    }

    // Add memory cleanup method
    cleanupMemory() {
        // Force garbage collection if available (only in development)
        if (window.gc && typeof window.gc === 'function') {
            setTimeout(() => window.gc(), 100);
        }
        
        // Clean up any stale event listeners or data
        this.checkAndCleanStaleReferences();
    }

    // Check for and clean stale references
    checkAndCleanStaleReferences() {
        // Remove any DOM elements that might be holding references
        const staleCards = document.querySelectorAll('.file-card:not([data-file-id])');
        staleCards.forEach(card => card.remove());
        
        // Validate filesData array for consistency
        if (this.filesData.length > 1000) {
            console.warn('Large files array detected:', this.filesData.length);
        }
    }

    // Confirm delete file
    confirmDeleteFile(fileId, filename) {
        window.ui.showDeleteModal(
            `Are you sure you want to delete "${filename}"?`,
            () => this.deleteFile(fileId)
        );
    }

    // Select file and navigate to analysis page
    selectAndAnalyze(fileId) {
        // Store selected file ID
        sessionStorage.setItem('selectedFileId', fileId);

        // Show loading overlay with progress messages
        const loadingOverlay = window.ui.get('loadingOverlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'flex';
            const loadingText = loadingOverlay.querySelector('p');
            if (loadingText) {
                loadingText.textContent = 'Starting analysis...';
            }
        }

        // Kick off backend analysis (now includes automatic Gemini domain assessment)
        (async () => {
            try {
                // Analyze PCAP (backend automatically calls Gemini to assess domains)
                if (loadingOverlay) {
                    const loadingText = loadingOverlay.querySelector('p');
                    if (loadingText) loadingText.textContent = 'Analyzing PCAP packets and classifying domains...';
                }
                window.ui.showStatus('Analyzing PCAP and classifying domains with AI…', 'info');
                await window.api.triggerAnalysis(fileId);
                
                window.ui.showStatus('Analysis complete!', 'success');
            } catch (e) {
                // Proceed anyway but warn
                console.error('Analysis error:', e);
                window.ui.showStatus(`Analysis completed with warnings: ${e.message || e}`, 'warning');
            } finally {
                // Navigate after background work
                if (loadingOverlay) {
                    const loadingText = loadingOverlay.querySelector('p');
                    if (loadingText) loadingText.textContent = 'Loading results...';
                }
                
                // Small delay to show final message
                setTimeout(() => {
                    window.location.href = 'analysis.html';
                }, 500);
            }
        })();
    }

    // Utility function
    getFileExtension(filename) {
        return filename.split('.').pop() || '';
    }
}

// Initialize File Manager
window.fileManager = new FileManager();

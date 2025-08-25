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
            
            const data = await window.api.get('/files');
            this.filesData = data.files || [];
            this.filteredFiles = [...this.filesData];
            
            console.log(`Loaded ${this.filesData.length} files`);
            
            this.renderFiles();
            this.updateAnalysisDropdown();
            this.updateStatistics();
            
        } catch (error) {
            console.error('Error loading files:', error);
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
        
        filesGrid.innerHTML = this.filteredFiles.map(file => `
            <div class="file-card" data-file-id="${file.id}">
                <div class="file-icon">
                    <i class="fas fa-file-alt"></i>
                </div>
                <div class="file-info">
                    <div class="file-name" title="${file.original_filename}">
                        ${window.ui.truncateFilename(file.original_filename, 30)}
                    </div>
                    <div class="file-meta">
                        ${file.size_formatted} • ${window.ui.formatDate(file.uploaded_at)}
                    </div>
                </div>
                <div class="file-actions">
                    <button class="btn" onclick="fileManager.downloadFile(${file.id}, '${file.original_filename.replace(/'/g, "\\'")}')">
                        <i class="fas fa-download"></i>
                        Download
                    </button>
                    <button class="btn btn-primary" onclick="fileManager.selectAndAnalyze(${file.id})">
                        <i class="fas fa-microscope"></i>
                        Analyze
                    </button>
                    <button class="btn btn-danger" onclick="fileManager.confirmDeleteFile(${file.id}, '${file.original_filename.replace(/'/g, "\\'")}')">
                        <i class="fas fa-trash"></i>
                        Delete
                    </button>
                </div>
            </div>
        `).join('');
    }

    // Update analysis dropdown
    updateAnalysisDropdown() {
        const analysisFileSelect = window.ui.get('analysisFileSelect');
        if (!analysisFileSelect) return;
        
        analysisFileSelect.innerHTML = '<option value="" disabled selected>Select a PCAP file...</option>';
        
        this.filesData.forEach(file => {
            const option = document.createElement('option');
            option.value = file.id;
            option.textContent = `${file.original_filename} (${file.size_formatted})`;
            analysisFileSelect.appendChild(option);
        });
    }

    // Update statistics
    updateStatistics() {
        const totalSize = this.filesData.reduce((sum, file) => sum + file.size, 0);
        
        window.ui.updateStats({
            totalFiles: this.filesData.length,
            totalSize: window.ui.formatFileSize(totalSize)
        });
    }

    // Filter files based on search
    filterFiles() {
        const searchInput = window.ui.get('searchInput');
        if (!searchInput) return;
        
        const searchTerm = searchInput.value.toLowerCase();
        
        if (!searchTerm) {
            this.filteredFiles = [...this.filesData];
        } else {
            this.filteredFiles = this.filesData.filter(file => 
                file.original_filename.toLowerCase().includes(searchTerm) ||
                file.filename.toLowerCase().includes(searchTerm) ||
                this.getFileExtension(file.filename).toLowerCase().includes(searchTerm)
            );
        }
        
        this.renderFiles();
    }

    // Sort files
    sortFiles() {
        const sortSelect = window.ui.get('sortSelect');
        if (!sortSelect) return;
        
        const sortBy = sortSelect.value;
        const sortedFiles = [...this.filteredFiles];
        
        switch (sortBy) {
            case 'date-desc':
                sortedFiles.sort((a, b) => new Date(b.uploaded_at) - new Date(a.uploaded_at));
                break;
            case 'date-asc':
                sortedFiles.sort((a, b) => new Date(a.uploaded_at) - new Date(b.uploaded_at));
                break;
            case 'name-asc':
                sortedFiles.sort((a, b) => a.original_filename.localeCompare(b.original_filename));
                break;
            case 'name-desc':
                sortedFiles.sort((a, b) => b.original_filename.localeCompare(a.original_filename));
                break;
            case 'size-desc':
                sortedFiles.sort((a, b) => b.size - a.size);
                break;
            case 'size-asc':
                sortedFiles.sort((a, b) => a.size - b.size);
                break;
        }
        
        this.filteredFiles = sortedFiles;
        this.renderFiles();
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
            
            window.ui.showStatus(result.message || 'File deleted successfully', 'success');
            this.loadFiles();
            
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
        
        window.ui.hideLoading();
        window.ui.showStatus(`Deleted ${deletedCount} files`, 'success');
        this.loadFiles();
    }

    // Confirm delete file
    confirmDeleteFile(fileId, filename) {
        window.ui.showDeleteModal(
            `Are you sure you want to delete "${filename}"?`,
            () => this.deleteFile(fileId)
        );
    }

    // Select file and switch to analysis tab
    selectAndAnalyze(fileId) {
        const analysisFileSelect = window.ui.get('analysisFileSelect');
        if (analysisFileSelect) {
            analysisFileSelect.value = String(fileId);
            window.ui.switchTab('analysis');
            
            // Trigger analysis refresh
            if (window.analysisManager) {
                window.analysisManager.refreshAnalysis();
            }
        }
    }

    // Utility function
    getFileExtension(filename) {
        return filename.split('.').pop() || '';
    }
}

// Initialize File Manager
window.fileManager = new FileManager();

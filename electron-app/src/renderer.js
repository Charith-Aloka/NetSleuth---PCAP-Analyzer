// NetSleuth PCAP Analyzer - Frontend JavaScript
const { ipcRenderer } = require('electron');

const API_URL = 'http://localhost:5000/api';
let filesData = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    console.log('NetSleuth PCAP Analyzer started');
    
    setupEventListeners();
    loadFiles();
    
    // Hide loading overlay
    setTimeout(() => {
        hideLoading();
    }, 1000);
});

function setupEventListeners() {
    // File input change
    document.getElementById('fileInput').addEventListener('change', handleFileSelect);
    
    // Drag and drop
    const uploadArea = document.getElementById('uploadArea');
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleDrop);
    
    // Menu events
    if (ipcRenderer) {
        ipcRenderer.on('menu-upload-file', () => {
            document.getElementById('fileInput').click();
        });
        
        ipcRenderer.on('menu-refresh', () => {
            loadFiles();
        });
    }
    
    // Search input
    document.getElementById('searchInput').addEventListener('input', filterFiles);
}

// Drag and Drop Handlers
function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.classList.add('drag-over');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.classList.remove('drag-over');
}

function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.classList.remove('drag-over');
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
        uploadFiles(files);
    }
}

// File Selection Handler
function handleFileSelect(e) {
    const files = Array.from(e.target.files);
    if (files.length > 0) {
        uploadFiles(files);
    }
}

// Upload Files
async function uploadFiles(files) {
    showProgress();
    
    let successCount = 0;
    let totalFiles = files.length;
    
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        
        try {
            updateProgress((i / totalFiles) * 100, `Uploading ${file.name}...`);
            
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch(`${API_URL}/upload`, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (response.ok) {
                successCount++;
                showStatus(`Uploaded: ${file.name}`, 'success');
            } else {
                if (response.status === 409) {
                    showStatus(`File already exists: ${file.name}`, 'info');
                } else {
                    showStatus(`Failed to upload ${file.name}: ${result.error}`, 'error');
                }
            }
            
        } catch (error) {
            showStatus(`Error uploading ${file.name}: ${error.message}`, 'error');
        }
    }
    
    updateProgress(100, `Upload complete! ${successCount}/${totalFiles} files uploaded.`);
    
    setTimeout(() => {
        hideProgress();
        loadFiles();
        // Reset file input
        document.getElementById('fileInput').value = '';
    }, 1500);
}

// Load Files from Backend
async function loadFiles() {
    try {
        showLoading();
        
        const response = await fetch(`${API_URL}/files`);
        const result = await response.json();
        
        if (response.ok) {
            filesData = result.files || [];
            renderFiles(filesData);
            updateStats(filesData);
        } else {
            showStatus('Failed to load files', 'error');
        }
        
    } catch (error) {
        console.error('Error loading files:', error);
        showStatus('Error loading files: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

// Render Files Grid
function renderFiles(files) {
    const filesGrid = document.getElementById('filesGrid');
    const emptyState = document.getElementById('emptyState');
    
    if (!files || files.length === 0) {
        filesGrid.style.display = 'none';
        emptyState.style.display = 'block';
        return;
    }
    
    filesGrid.style.display = 'grid';
    emptyState.style.display = 'none';
    
    filesGrid.innerHTML = files.map(file => `
        <div class="file-card" data-file-id="${file.id}">
            <div class="file-header">
                <div class="file-icon">
                    <i class="fas fa-file-alt"></i>
                </div>
                <div class="file-menu">
                    <button class="file-menu-btn" onclick="toggleFileMenu(${file.id})">
                        <i class="fas fa-ellipsis-v"></i>
                    </button>
                </div>
            </div>
            <div class="file-info">
                <h4 title="${file.original_filename}">${truncateFilename(file.original_filename, 30)}</h4>
                <div class="file-details">
                    <div class="detail-item">
                        <span class="detail-label">Size</span>
                        <span class="detail-value">${file.size_formatted}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Type</span>
                        <span class="detail-value">${getFileExtension(file.filename).toUpperCase()}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Uploaded</span>
                        <span class="detail-value">${formatDate(file.uploaded_at)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">SHA256</span>
                        <span class="detail-value" title="${file.sha256}">${file.sha256.substring(0, 8)}...</span>
                    </div>
                </div>
                <div class="file-actions">
                    <button class="btn btn-primary" onclick="downloadFile(${file.id}, '${file.original_filename}')">
                        <i class="fas fa-download"></i>
                        Download
                    </button>
                    <button class="btn btn-danger" onclick="confirmDeleteFile(${file.id}, '${file.original_filename.replace(/'/g, "\\'")}')">
                        <i class="fas fa-trash"></i>
                        Delete
                    </button>
                </div>
            </div>
        </div>
    `).join('');
}

// Download File
async function downloadFile(fileId, filename) {
    try {
        showStatus(`Downloading ${filename}...`, 'info');
        
        const response = await fetch(`${API_URL}/download/${fileId}`);
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
            
            showStatus(`Downloaded: ${filename}`, 'success');
        } else {
            const error = await response.json();
            showStatus(`Download failed: ${error.error}`, 'error');
        }
        
    } catch (error) {
        console.error('Download error:', error);
        showStatus(`Download error: ${error.message}`, 'error');
    }
}

// Delete File
async function deleteFile(fileId) {
    try {
        const response = await fetch(`${API_URL}/delete/${fileId}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showStatus(result.message, 'success');
            loadFiles();
        } else {
            showStatus(`Delete failed: ${result.error}`, 'error');
        }
        
    } catch (error) {
        console.error('Delete error:', error);
        showStatus(`Delete error: ${error.message}`, 'error');
    }
}

// Confirm Delete File
function confirmDeleteFile(fileId, filename) {
    const modal = document.getElementById('deleteModal');
    const message = document.getElementById('deleteMessage');
    const confirmBtn = document.getElementById('confirmDeleteBtn');
    
    message.textContent = `Are you sure you want to delete "${filename}"?`;
    
    confirmBtn.onclick = () => {
        deleteFile(fileId);
        closeDeleteModal();
    };
    
    modal.style.display = 'flex';
}

// Close Delete Modal
function closeDeleteModal() {
    document.getElementById('deleteModal').style.display = 'none';
}

// Confirm Delete All Files
function confirmDeleteAll() {
    if (filesData.length === 0) {
        showStatus('No files to delete', 'info');
        return;
    }
    
    const modal = document.getElementById('deleteModal');
    const message = document.getElementById('deleteMessage');
    const confirmBtn = document.getElementById('confirmDeleteBtn');
    
    message.textContent = `Are you sure you want to delete all ${filesData.length} files? This action cannot be undone.`;
    
    confirmBtn.onclick = () => {
        deleteAllFiles();
        closeDeleteModal();
    };
    
    modal.style.display = 'flex';
}

// Delete All Files
async function deleteAllFiles() {
    showLoading();
    
    let deletedCount = 0;
    for (const file of filesData) {
        try {
            const response = await fetch(`${API_URL}/delete/${file.id}`, {
                method: 'DELETE'
            });
            
            if (response.ok) {
                deletedCount++;
            }
        } catch (error) {
            console.error(`Error deleting file ${file.id}:`, error);
        }
    }
    
    hideLoading();
    showStatus(`Deleted ${deletedCount} files`, 'success');
    loadFiles();
}

// Filter Files
function filterFiles() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    
    if (!searchTerm) {
        renderFiles(filesData);
        return;
    }
    
    const filteredFiles = filesData.filter(file => 
        file.original_filename.toLowerCase().includes(searchTerm) ||
        file.filename.toLowerCase().includes(searchTerm) ||
        getFileExtension(file.filename).toLowerCase().includes(searchTerm)
    );
    
    renderFiles(filteredFiles);
}

// Sort Files
function sortFiles() {
    const sortBy = document.getElementById('sortSelect').value;
    const sortedFiles = [...filesData];
    
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
    
    renderFiles(sortedFiles);
}

// Update Statistics
function updateStats(files) {
    const totalFiles = files.length;
    const totalSize = files.reduce((sum, file) => sum + file.size, 0);
    
    document.getElementById('totalFiles').textContent = totalFiles;
    document.getElementById('totalSize').textContent = formatFileSize(totalSize);
}

// Show/Hide Progress
function showProgress() {
    document.getElementById('uploadProgress').style.display = 'block';
}

function hideProgress() {
    document.getElementById('uploadProgress').style.display = 'none';
}

function updateProgress(percent, text) {
    document.getElementById('progressFill').style.width = `${percent}%`;
    document.getElementById('progressText').textContent = text;
}

// Show/Hide Loading
function showLoading() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

// Show Status Message
function showStatus(message, type = 'info') {
    const container = document.getElementById('statusContainer');
    const statusDiv = document.createElement('div');
    statusDiv.className = `status-message ${type}`;
    
    let icon = 'fas fa-info-circle';
    if (type === 'success') icon = 'fas fa-check-circle';
    else if (type === 'error') icon = 'fas fa-exclamation-circle';
    
    statusDiv.innerHTML = `
        <i class="${icon}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(statusDiv);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (statusDiv.parentNode) {
            statusDiv.parentNode.removeChild(statusDiv);
        }
    }, 5000);
}

// Utility Functions
function truncateFilename(filename, maxLength) {
    if (filename.length <= maxLength) return filename;
    
    const ext = getFileExtension(filename);
    const nameWithoutExt = filename.substring(0, filename.lastIndexOf('.'));
    const truncated = nameWithoutExt.substring(0, maxLength - ext.length - 4) + '...';
    
    return truncated + '.' + ext;
}

function getFileExtension(filename) {
    return filename.split('.').pop() || '';
}

function formatDate(isoString) {
    const date = new Date(isoString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Close modal when clicking outside
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal-overlay')) {
        closeDeleteModal();
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // ESC to close modal
    if (e.key === 'Escape') {
        closeDeleteModal();
    }
    
    // Ctrl+O to open file dialog
    if (e.ctrlKey && e.key === 'o') {
        e.preventDefault();
        document.getElementById('fileInput').click();
    }
    
    // F5 to refresh
    if (e.key === 'F5') {
        e.preventDefault();
        loadFiles();
    }
});

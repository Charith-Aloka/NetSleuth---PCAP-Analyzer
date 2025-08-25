const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
    // Menu events
    onMenuUploadFile: (callback) => ipcRenderer.on('menu-upload-file', callback),
    onMenuAnalyzeSelected: (callback) => ipcRenderer.on('menu-analyze-selected', callback),
    onMenuGenerateReport: (callback) => ipcRenderer.on('menu-generate-report', callback),
    
    // File operations
    openFileDialog: () => ipcRenderer.invoke('dialog:openFile'),
    saveFileDialog: (options) => ipcRenderer.invoke('dialog:saveFile', options),
    
    // System info
    getPlatform: () => process.platform,
    getVersion: () => process.version,
    
    // Remove listeners
    removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});
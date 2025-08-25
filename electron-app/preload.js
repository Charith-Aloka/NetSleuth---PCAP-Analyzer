const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
    // File operations
    uploadFile: () => ipcRenderer.send('upload-file'),
    
    // Menu events
    onMenuUploadFile: (callback) => ipcRenderer.on('menu-upload-file', callback),
    onMenuRefresh: (callback) => ipcRenderer.on('menu-refresh', callback),
    
    // Remove listeners
    removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel),
    
    // App info
    getVersion: () => process.env.npm_package_version || '1.0.0',
    getPlatform: () => process.platform,
    
    // Development
    isDev: () => process.argv.includes('--dev')
});

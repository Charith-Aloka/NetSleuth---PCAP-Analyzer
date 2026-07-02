const { contextBridge, ipcRenderer } = require('electron');

// Expose a minimal, safe API to the renderer
contextBridge.exposeInMainWorld('electronAPI', {
  onMenuUploadFile: (callback) => {
    const listener = () => callback();
    ipcRenderer.on('menu-upload-file', listener);
    return () => ipcRenderer.removeListener('menu-upload-file', listener);
  },
  onMenuRefresh: (callback) => {
    const listener = () => callback();
    ipcRenderer.on('menu-refresh', listener);
    return () => ipcRenderer.removeListener('menu-refresh', listener);
  },
  isDev: () => process.argv.includes('--dev')
});

const { app, BrowserWindow, Menu, dialog, shell, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let backendProcess;

// Backend server management
function startBackendServer() {
    const backendPath = path.join(__dirname, '..', 'backend');
    const pythonScript = path.join(backendPath, 'app.py');
    
    console.log('Starting backend server...');
    backendProcess = spawn('python', [pythonScript], {
        cwd: backendPath,
        stdio: ['ignore', 'pipe', 'pipe']
    });
    
    backendProcess.stdout.on('data', (data) => {
        console.log('Backend stdout:', data.toString());
    });
    
    backendProcess.stderr.on('data', (data) => {
        console.log('Backend stderr:', data.toString());
    });
    
    backendProcess.on('close', (code) => {
        console.log('Backend server stopped');
    });
    
    backendProcess.on('error', (error) => {
        console.error('Backend server error:', error);
        dialog.showErrorBox('Backend Error', `Failed to start backend server: ${error.message}`);
    });
    
    console.log('Backend server started');
}

function stopBackendServer() {
    if (backendProcess) {
        backendProcess.kill();
        backendProcess = null;
        console.log('Backend server stopped');
    }
}

function createWindow() {
    // Create the browser window with memory optimizations
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 800,
        minHeight: 600,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            enableRemoteModule: false,
            preload: path.join(__dirname, 'preload.js'),
            // Memory optimization settings
            webSecurity: true,
            allowRunningInsecureContent: false,
            experimentalFeatures: false,
            backgroundThrottling: true,
            // Enable V8 memory optimization
            additionalArguments: [
                '--max-old-space-size=512',           // Limit V8 heap to 512MB
                '--optimize-for-size',                 // Optimize for memory usage
                '--memory-reducer',                    // Enable memory reducer
                '--gc-interval=100'                    // More frequent garbage collection
            ]
        },
        icon: path.join(__dirname, 'src', 'assets', 'icon.png'),
        show: false,
        titleBarStyle: 'default'
    });
    
    // Load the app
    mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));
    
    // Show window when ready
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
        
        // Focus on window (Windows/Linux)
        if (process.platform === 'win32' || process.platform === 'linux') {
            mainWindow.focus();
        }
        
        // Log initial memory usage
        setTimeout(() => {
            const memoryUsage = process.memoryUsage();
            console.log('🔍 Initial memory usage:', {
                'RSS': `${(memoryUsage.rss / 1024 / 1024).toFixed(1)}MB`,
                'Heap Used': `${(memoryUsage.heapUsed / 1024 / 1024).toFixed(1)}MB`,
                'Heap Total': `${(memoryUsage.heapTotal / 1024 / 1024).toFixed(1)}MB`,
                'External': `${(memoryUsage.external / 1024 / 1024).toFixed(1)}MB`
            });
        }, 2000);
    });

    // Handle window closing
    mainWindow.on('close', (event) => {
        // Execute cleanup before closing
        mainWindow.webContents.executeJavaScript(`
            // Stop memory monitoring
            if (window.memoryMonitor) {
                window.memoryMonitor.stop();
            }
            
            // Clear large data structures
            if (window.fileManager) {
                window.fileManager.filesData = [];
                window.fileManager.filteredFiles = [];
            }
            
            if (window.analysisManager) {
                window.analysisManager.analysisData = null;
            }
            
            // Force garbage collection if available
            if (window.gc) {
                window.gc();
            }
            
            console.log('🧹 Memory cleanup completed before window close');
        `).catch(err => console.log('Cleanup error:', err));
    });

    // Handle window closed
    mainWindow.on('closed', () => {
        mainWindow = null;
        
        // Force garbage collection on main process
        if (global.gc) {
            global.gc();
            console.log('🧹 Main process garbage collection completed');
        }
    });
    
    // Handle external links
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        shell.openExternal(url);
        return { action: 'deny' };
    });
    
    // Development tools
    if (process.argv.includes('--dev')) {
        mainWindow.webContents.openDevTools();
    }
    
    // Start backend server
    startBackendServer();
}

// Application menu
function createMenu() {
    const template = [
        {
            label: 'File',
            submenu: [
                {
                    label: 'Upload PCAP File',
                    accelerator: 'CmdOrCtrl+O',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.webContents.send('menu-upload-file');
                        }
                    }
                },
                { type: 'separator' },
                {
                    label: 'Refresh',
                    accelerator: 'F5',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.webContents.send('menu-refresh');
                        }
                    }
                },
                { type: 'separator' },
                {
                    label: 'Exit',
                    accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Ctrl+Q',
                    click: () => {
                        app.quit();
                    }
                }
            ]
        },
        {
            label: 'View',
            submenu: [
                { role: 'reload' },
                { role: 'forceReload' },
                { role: 'toggleDevTools' },
                { type: 'separator' },
                { role: 'resetZoom' },
                { role: 'zoomIn' },
                { role: 'zoomOut' },
                { type: 'separator' },
                { role: 'togglefullscreen' }
            ]
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'About',
                    click: () => {
                        dialog.showMessageBox(mainWindow, {
                            type: 'info',
                            title: 'About PCAP Analyzer',
                            message: 'PCAP Analyzer v1.0.0',
                            detail: 'Network traffic analysis tool powered by Scapy\\n\\nBuilt with Electron and Python Flask'
                        });
                    }
                }
            ]
        }
    ];
    
    // macOS specific menu adjustments
    if (process.platform === 'darwin') {
        template.unshift({
            label: app.getName(),
            submenu: [
                { role: 'about' },
                { type: 'separator' },
                { role: 'services' },
                { type: 'separator' },
                { role: 'hide' },
                { role: 'hideOthers' },
                { role: 'unhide' },
                { type: 'separator' },
                { role: 'quit' }
            ]
        });
    }
    
    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

// App event handlers
app.whenReady().then(() => {
    createWindow();
    createMenu();
    
    app.on('activate', () => {
        // On macOS, re-create window when dock icon is clicked
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    // Stop backend server when app is closing
    stopBackendServer();
    
    // On macOS, keep app running even when all windows are closed
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('before-quit', () => {
    stopBackendServer();
});

// Security: Prevent new window creation
app.on('web-contents-created', (event, contents) => {
    contents.on('new-window', (event, navigationUrl) => {
        event.preventDefault();
        shell.openExternal(navigationUrl);
    });
});

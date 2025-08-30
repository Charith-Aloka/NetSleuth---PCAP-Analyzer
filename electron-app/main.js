const { app, BrowserWindow, Menu, dialog, shell } = require('electron');
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
    // Create the browser window
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 800,
        minHeight: 600,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            enableRemoteModule: false,
            preload: path.join(__dirname, 'preload.js')
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
    });
    
    // Handle window closed
    mainWindow.on('closed', () => {
        mainWindow = null;
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

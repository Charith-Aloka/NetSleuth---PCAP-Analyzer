const { app, BrowserWindow, Menu, dialog } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

let mainWindow;
let backendProcess;

// Create the main application window
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 700,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        },
        show: false
    });

    mainWindow.loadFile('src/index.html');

    // Show window when ready
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
        
        // Start backend server
        startBackendServer();
    });

    // Handle window closed
    mainWindow.on('closed', () => {
        mainWindow = null;
        stopBackendServer();
    });

    // Create application menu
    createMenu();

    // Open DevTools in development
    if (process.argv.includes('--dev')) {
        mainWindow.webContents.openDevTools();
    }
}

function startBackendServer() {
    const backendPath = path.join(__dirname, '..', 'backend');
    const pythonScript = path.join(backendPath, 'app.py');

    try {
        // Start Python backend
        backendProcess = spawn('python', [pythonScript], {
            cwd: backendPath,
            stdio: 'pipe'
        });

        backendProcess.stdout.on('data', (data) => {
            console.log(`Backend stdout: ${data}`);
        });

        backendProcess.stderr.on('data', (data) => {
            console.error(`Backend stderr: ${data}`);
        });

        backendProcess.on('close', (code) => {
            console.log(`Backend process exited with code ${code}`);
        });

        console.log('Backend server started');
    } catch (error) {
        console.error('Failed to start backend server:', error);
        dialog.showErrorBox('Backend Error', 'Failed to start the backend server. Please ensure Python is installed.');
    }
}

function stopBackendServer() {
    if (backendProcess) {
        backendProcess.kill();
        backendProcess = null;
        console.log('Backend server stopped');
    }
}

function createMenu() {
    const template = [
        {
            label: 'File',
            submenu: [
                {
                    label: 'Upload PCAP File',
                    accelerator: 'CmdOrCtrl+O',
                    click: () => {
                        mainWindow.webContents.send('menu-upload-file');
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
                {
                    label: 'Refresh',
                    accelerator: 'CmdOrCtrl+R',
                    click: () => {
                        mainWindow.webContents.send('menu-refresh');
                    }
                },
                { type: 'separator' },
                {
                    label: 'Toggle Developer Tools',
                    accelerator: process.platform === 'darwin' ? 'Alt+Cmd+I' : 'Ctrl+Shift+I',
                    click: () => {
                        mainWindow.webContents.toggleDevTools();
                    }
                }
            ]
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'About NetSleuth',
                    click: () => {
                        dialog.showMessageBox(mainWindow, {
                            type: 'info',
                            title: 'About NetSleuth PCAP Analyzer',
                            message: 'NetSleuth PCAP Analyzer v1.0.0',
                            detail: 'A powerful tool for uploading, managing, and analyzing PCAP files.\n\nBuilt with Electron and Flask.'
                        });
                    }
                }
            ]
        }
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

// App event handlers
app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    stopBackendServer();
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('before-quit', () => {
    stopBackendServer();
});

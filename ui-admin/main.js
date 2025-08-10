const { app, BrowserWindow, Menu, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const axios = require('axios');

let mainWindow;
let coreService;
const API_BASE = 'http://127.0.0.1:8081/api/v1';

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        },
        icon: path.join(__dirname, 'assets/icon.ico'),
        titleBarStyle: 'default'
    });

    mainWindow.loadFile('renderer/index.html');
    
    // Development tools
    if (process.env.NODE_ENV === 'development') {
        mainWindow.webContents.openDevTools();
    }
}

function startCoreService() {
    const servicePath = path.join(__dirname, '../core-service/core-service.exe');
    coreService = spawn(servicePath, [], {
        detached: false,
        stdio: 'inherit'
    });
    
    coreService.on('error', (err) => {
        console.error('Failed to start core service:', err);
        dialog.showErrorBox('Service Error', 'Failed to start core service');
    });
}

app.whenReady().then(() => {
    createWindow();
    startCoreService();
    
    // Create menu
    const template = [
        {
            label: 'File',
            submenu: [
                { role: 'quit' }
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
                { role: 'zoomOut' }
            ]
        }
    ];
    
    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
});

app.on('window-all-closed', () => {
    if (coreService) {
        coreService.kill();
    }
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

// IPC handlers
ipcMain.handle('api-call', async (event, method, endpoint, data) => {
    try {
        const config = {
            method: method.toLowerCase(),
            url: `${API_BASE}${endpoint}`,
            headers: {
                'Content-Type': 'application/json'
            }
        };
        
        if (data) {
            config.data = data;
        }
        
        const response = await axios(config);
        return { success: true, data: response.data };
    } catch (error) {
        console.error('API call failed:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('show-auth-dialog', async () => {
    const result = await dialog.showMessageBox(mainWindow, {
        type: 'question',
        buttons: ['Cancel', 'Enter Password'],
        defaultId: 1,
        title: 'Administrator Access',
        message: 'Enter administrator password to continue:',
        detail: 'This action requires administrator privileges.'
    });
    
    return result.response === 1;
});

const { app, BrowserWindow, Menu, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { spawn, exec } = require('child_process');
const axios = require('axios');

// Global variables
let mainWindow;
let coreProcess = null;
let isStartingService = false;
let serviceStartTime = null;

// Utility functions
function isPortAvailable(port) {
    return new Promise((resolve) => {
        const server = net.createServer();
        server.listen(port, () => {
            server.close(() => resolve(true));
        });
        server.on('error', () => resolve(false));
    });
}

function checkAdminRights() {
    return new Promise((resolve) => {
        exec('net session', (error, stdout, stderr) => {
            resolve(!error);
        });
    });
}

async function requestAdminRights() {
    try {
        if (process.platform === 'win32') {
            const isAdmin = await checkAdminRights();
            if (!isAdmin) {
                dialog.showErrorBox(
                    'Administrator Rights Required',
                    'This application requires administrator privileges. Please restart as administrator.'
                );
                app.quit();
                return false;
            }
        }
        return true;
    } catch (error) {
        console.error('Error checking admin rights:', error);
        return false;
    }
}

// Kill existing processes function
function killExistingProcesses() {
    return new Promise((resolve) => {
        exec('tasklist /fi "imagename eq parental-control-core.exe" /fo csv', (error, stdout) => {
            if (error || !stdout) {
                resolve();
                return;
            }

            const lines = stdout.split('\n');
            const pids = [];

            for (let i = 1; i < lines.length; i++) {
                const line = lines[i].trim();
                if (line) {
                    const parts = line.split(',');
                    if (parts.length > 1) {
                        const pid = parts[1].replace(/"/g, '');
                        pids.push(pid);
                    }
                }
            }

            if (pids.length === 0) {
                resolve();
                return;
            }

            console.log(`Killing ${pids.length} existing processes:`, pids);
            const killCommands = pids.map(pid => `taskkill /PID ${pid} /F`);

            exec(killCommands.join(' && '), (err) => {
                setTimeout(resolve, 1000); // Wait 1 second after killing
            });
        });
    });
}

// FIXED Core service management
async function startCoreService() {
    // Strict prevent multiple calls
    if (isStartingService) {
        console.log('Service startup already in progress, aborting...');
        return;
    }

    // Check if service started recently (within 10 seconds)
    if (serviceStartTime && (Date.now() - serviceStartTime < 10000)) {
        console.log('Service started recently, skipping...');
        return;
    }

    isStartingService = true;
    serviceStartTime = Date.now();

    try {
        console.log('Killing any existing processes...');
        await killExistingProcesses();

        console.log('Checking port availability...');
        const apiPortAvailable = await isPortAvailable(8081);
        if (!apiPortAvailable) {
            console.log('Port 8081 still busy after killing processes, waiting...');
            await new Promise(resolve => setTimeout(resolve, 2000));
        }

        startActualService();

    } catch (error) {
        console.error('Error in startCoreService:', error);
        isStartingService = false;
    }
}

function startActualService() {
    try {
        console.log('Starting core service...');

        const exePath = path.join(__dirname, 'parental-control-core.exe');

        if (!fs.existsSync(exePath)) {
            console.error(`Core service executable not found at: ${exePath}`);
            isStartingService = false;
            return;
        }

        // Set current process reference
        coreProcess = spawn(exePath, [], {
            cwd: __dirname,
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true,
            detached: false
        });

        coreProcess.stdout.on('data', (data) => {
            console.log(`Core service: ${data.toString().trim()}`);
        });

        coreProcess.stderr.on('data', (data) => {
            console.error(`Core service error: ${data.toString().trim()}`);
        });

        coreProcess.on('error', (error) => {
            console.error('Core process error:', error);
            coreProcess = null;
            isStartingService = false;
            serviceStartTime = null;
        });

        coreProcess.on('exit', (code, signal) => {
            console.log(`Core service exited with code ${code}, signal ${signal}`);
            coreProcess = null;
            isStartingService = false;
            serviceStartTime = null;

            // Only restart if crashed unexpectedly
            if (signal !== 'SIGTERM' && signal !== 'SIGKILL' && code !== 0) {
                console.log('Service crashed, will restart in 5 seconds...');
                setTimeout(() => {
                    if (!coreProcess && !isStartingService) {
                        startCoreService();
                    }
                }, 5000);
            }
        });

        // Mark as successfully started after 2 seconds
        setTimeout(() => {
            if (coreProcess && !coreProcess.killed) {
                console.log('Core service started successfully');
                isStartingService = false;
            }
        }, 2000);

    } catch (error) {
        console.error('Error starting service:', error);
        coreProcess = null;
        isStartingService = false;
        serviceStartTime = null;
    }
}

// Enhanced cleanup function
function cleanup() {
    if (coreProcess && !coreProcess.killed) {
        console.log('Stopping core service...');
        coreProcess.kill('SIGTERM');

        // Force kill after 3 seconds if not terminated
        setTimeout(() => {
            if (coreProcess && !coreProcess.killed) {
                console.log('Force killing core service...');
                coreProcess.kill('SIGKILL');
            }
        }, 3000);
    }

    // Kill any remaining processes
    exec('taskkill /IM "parental-control-core.exe" /F /T 2>nul', () => {});
}

// Electron app functions
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        },
        icon: path.join(__dirname, 'assets', 'icon.png')
    });

    mainWindow.loadFile('index.html');

    // Remove menu bar in production
    Menu.setApplicationMenu(null);

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// App event handlers
app.whenReady().then(async () => {
    const hasAdmin = await requestAdminRights();
    if (hasAdmin) {
        createWindow();
        
        // Wait a bit before starting core service
        setTimeout(() => {
            startCoreService();
        }, 1000);
    }
});

app.on('window-all-closed', () => {
    cleanup();
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

app.on('before-quit', cleanup);

// IPC handlers for the UI
ipcMain.handle('get-stats', async () => {
    try {
        const response = await axios.get('http://127.0.0.1:8081/api/v1/stats');
        return response.data;
    } catch (error) {
        console.error('Failed to get stats:', error);
        return { error: 'Failed to connect to service' };
    }
});

ipcMain.handle('get-rules', async () => {
    try {
        const response = await axios.get('http://127.0.0.1:8081/api/v1/rules');
        return response.data;
    } catch (error) {
        console.error('Failed to get rules:', error);
        return [];
    }
});

ipcMain.handle('add-rule', async (event, rule) => {
    try {
        const response = await axios.post('http://127.0.0.1:8081/api/v1/rules', rule);
        return response.data;
    } catch (error) {
        console.error('Failed to add rule:', error);
        return { error: 'Failed to add rule' };
    }
});

ipcMain.handle('delete-rule', async (event, ruleId) => {
    try {
        const response = await axios.delete(`http://127.0.0.1:8081/api/v1/rules/${ruleId}`);
        return response.data;
    } catch (error) {
        console.error('Failed to delete rule:', error);
        return { error: 'Failed to delete rule' };
    }
});

ipcMain.handle('get-logs', async () => {
    try {
        const response = await axios.get('http://127.0.0.1:8081/api/v1/logs');
        return response.data;
    } catch (error) {
        console.error('Failed to get logs:', error);
        return [];
    }
});

ipcMain.handle('get-system-status', async () => {
    try {
        const response = await axios.get('http://127.0.0.1:8081/api/v1/system/status');
        return response.data;
    } catch (error) {
        console.error('Failed to get system status:', error);
        return { error: 'Failed to connect to service' };
    }
});

ipcMain.handle('configure-system', async () => {
    try {
        const response = await axios.post('http://127.0.0.1:8081/api/v1/system/configure');
        return response.data;
    } catch (error) {
        console.error('Failed to configure system:', error);
        return { error: 'Failed to configure system' };
    }
});

ipcMain.handle('restore-system', async () => {
    try {
        const response = await axios.post('http://127.0.0.1:8081/api/v1/system/restore');
        return response.data;
    } catch (error) {
        console.error('Failed to restore system:', error);
        return { error: 'Failed to restore system' };
    }
});

ipcMain.handle('restart-core-service', async () => {
    try {
        cleanup();
        await new Promise(resolve => setTimeout(resolve, 2000));
        await startCoreService();
        return { status: 'success', message: 'Service restarted' };
    } catch (error) {
        console.error('Failed to restart service:', error);
        return { error: 'Failed to restart service' };
    }
});

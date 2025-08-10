const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

function buildCoreService() {
    try {
        const coreServicePath = path.join(__dirname, '..', 'core-service');
        const exePath = path.join(__dirname, 'parental-control-core.exe');
        
        console.log('Building core service...');
        
        // Build Go executable
        execSync('go build -o parental-control-core.exe', {
            cwd: coreServicePath,
            stdio: 'inherit'
        });
        
        // Copy to ui-admin directory
        const sourceExe = path.join(coreServicePath, 'parental-control-core.exe');
        if (fs.existsSync(sourceExe)) {
            fs.copyFileSync(sourceExe, exePath);
            console.log('Core service built and copied successfully!');
        } else {
            throw new Error('Build failed - executable not created');
        }
        
    } catch (error) {
        console.error('Build failed:', error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    buildCoreService();
}

module.exports = { buildCoreService };

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const rootDir = __dirname;
const venvPy = path.join(rootDir, '.venv', 'Scripts', 'python.exe');
const pythonCmd = fs.existsSync(venvPy) ? venvPy : 'py';

console.log(`\x1b[36m[Phishing Attack Defender]\x1b[0m Launching backend using: ${pythonCmd}`);
const child = spawn(pythonCmd, [path.join(rootDir, 'backend', 'app.py')], {
  cwd: rootDir,
  stdio: 'inherit',
  shell: true,
});

child.on('exit', (code) => {
  process.exit(code || 0);
});

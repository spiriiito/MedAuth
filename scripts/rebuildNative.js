const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const rootDir = path.resolve(__dirname, '..');
const projectNodeVersion = fs.readFileSync(path.join(rootDir, '.nvmrc'), 'utf8').trim().replace(/^v/, '');
const expectedVersion = `v${projectNodeVersion}`;
const projectNodeBin = path.join(os.homedir(), '.nvm', 'versions', 'node', `v${projectNodeVersion}`, 'bin');
const projectNpm = path.join(projectNodeBin, 'npm');

if (!fs.existsSync(projectNpm)) {
  console.error(`Expected npm not found at ${projectNpm}. Run "nvm install" in this directory.`);
  process.exit(1);
}

if (process.version !== expectedVersion) {
  console.log(`Rebuilding native modules with Node ${expectedVersion} instead of ${process.version}`);
}

const result = spawnSync(projectNpm, ['rebuild', 'better-sqlite3'], {
  cwd: rootDir,
  env: {
    ...process.env,
    PATH: `${projectNodeBin}${path.delimiter}${process.env.PATH || ''}`,
  },
  stdio: 'inherit',
});

if (result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status ?? 1);

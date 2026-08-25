const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const rootDir = path.resolve(__dirname, '..');
const nvmrcPath = path.join(rootDir, '.nvmrc');
const targetScript = process.argv[2];
const targetArgs = process.argv.slice(3);

if (!targetScript) {
  console.error('Usage: node scripts/runWithProjectNode.js <script> [...args]');
  process.exit(1);
}

const projectNodeVersion = fs.readFileSync(nvmrcPath, 'utf8').trim().replace(/^v/, '');
const expectedVersion = `v${projectNodeVersion}`;

function nvmNodePath(version) {
  return path.join(os.homedir(), '.nvm', 'versions', 'node', `v${version}`, 'bin', 'node');
}

if (process.version !== expectedVersion) {
  const projectNode = nvmNodePath(projectNodeVersion);

  if (!fs.existsSync(projectNode)) {
    console.error(`This project requires Node ${expectedVersion}, but current Node is ${process.version}.`);
    console.error(`Expected Node executable not found at ${projectNode}. Run "nvm install" in this directory.`);
    process.exit(1);
  }

  const projectNodeBin = path.dirname(projectNode);
  const result = spawnSync(projectNode, [targetScript, ...targetArgs], {
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
}

require(path.resolve(rootDir, targetScript));

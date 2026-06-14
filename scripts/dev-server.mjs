import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';

const root = path.resolve(process.cwd());

function start(command, args, label) {
  const child = spawn(command, args, {
    cwd: root,
    stdio: ['inherit', 'pipe', 'pipe'],
    shell: false,
    env: process.env,
  });

  child.stdout.on('data', (data) => process.stdout.write(`[${label}] ${data}`));
  child.stderr.on('data', (data) => process.stderr.write(`[${label}] ${data}`));

  return child;
}

function canRunPythonBackend() {
  if (!process.env.MONGO_URI || !process.env.SECRET_KEY) {
    return false;
  }

  const pythonCheck = spawnSync('python', ['--version'], {
    cwd: root,
    stdio: 'ignore',
    shell: false,
  });

  return pythonCheck.status === 0;
}

const backend = canRunPythonBackend()
  ? start('python', ['Back-end/app.py'], 'backend')
  : start(process.execPath, ['server/mock-backend.mjs'], 'backend');
const frontend = start(process.execPath, ['node_modules/vite/bin/vite.js'], 'vite');

const shutdown = () => {
  backend.kill();
  frontend.kill();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

backend.on('exit', (code) => {
  if (code !== 0) {
    frontend.kill();
    process.exit(code ?? 1);
  }
});

frontend.on('exit', (code) => {
  if (code !== 0) {
    backend.kill();
    process.exit(code ?? 1);
  }
});

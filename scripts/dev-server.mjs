import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.cwd());

function loadEnvFile(filePath) {
  if (!existsSync(filePath)) {
    return;
  }

  const content = readFileSync(filePath, 'utf8');

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    if (!key || process.env[key] !== undefined) {
      continue;
    }

    let value = line.slice(separatorIndex + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    process.env[key] = value;
  }
}

[
  path.join(root, 'Back-end', 'Backend', '.env'),
  path.join(root, 'Back-end', '.env'),
  path.join(root, 'Back-end', '.env.local'),
  path.join(root, '.env'),
  path.join(root, '.env.local'),
  path.join(root, '.vercel', '.env.development.local'),
  path.join(root, '.vercel', '.env.preview.local'),
  path.join(root, '.vercel', '.env.production.local'),
].forEach(loadEnvFile);

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
  const pythonCheck = spawnSync('python', ['--version'], {
    cwd: root,
    stdio: 'ignore',
    shell: false,
  });

  return pythonCheck.status === 0 && Boolean(process.env.MONGO_URI) && Boolean(process.env.SECRET_KEY);
}
if (!canRunPythonBackend()) {
  throw new Error('Python backend requires MONGO_URI and SECRET_KEY to be set.');
}

const backend = start('python', ['Back-end/Backend/app.py'], 'backend');
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

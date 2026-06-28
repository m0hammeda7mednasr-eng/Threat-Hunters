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

function commandWorks(command, args = ['--version']) {
  const check = spawnSync(command, args, {
    cwd: root,
    stdio: 'ignore',
    shell: false,
  });
  return check.status === 0;
}

async function waitForBackendReady({ url, timeoutMs, backend }) {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    if (backend.exitCode !== null) {
      throw new Error(`Python backend exited early with code ${backend.exitCode}.`);
    }

    try {
      const response = await fetch(url, { method: 'GET' });
      if (response.ok) {
        return;
      }
    } catch {
      // Keep polling until the backend begins accepting requests.
    }

    await new Promise((resolve) => setTimeout(resolve, 350));
  }

  throw new Error(`Timed out waiting for backend readiness at ${url}.`);
}

function resolvePython() {
  const candidates = [
    process.env.PYTHON,
    path.join(root, '.venv', 'Scripts', 'python.exe'),
    path.join(root, '.venv', 'bin', 'python'),
    path.join(root, 'Back-end', 'Backend', '.venv', 'Scripts', 'python.exe'),
    path.join(root, 'Back-end', 'Backend', '.venv', 'bin', 'python'),
    'python',
  ].filter(Boolean);

  for (const command of candidates) {
    if ((command.includes(path.sep) || command.endsWith('.exe')) && !existsSync(command)) {
      continue;
    }
    if (commandWorks(command)) {
      return { command, argsPrefix: [] };
    }
  }

  if (commandWorks('py', ['-3', '--version'])) {
    return { command: 'py', argsPrefix: ['-3'] };
  }

  return null;
}

const python = resolvePython();
function canRunPythonBackend() {
  return Boolean(python) && Boolean(process.env.MONGO_URI) && Boolean(process.env.SECRET_KEY);
}

if (!canRunPythonBackend()) {
  throw new Error('Python backend requires a working Python interpreter plus MONGO_URI and SECRET_KEY.');
}

const backend = start(python.command, [...python.argsPrefix, 'Back-end/Backend/app.py'], 'backend');
var frontend = null;

const shutdown = () => {
  backend.kill();
  frontend?.kill();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

backend.on('exit', (code) => {
  if (code !== 0) {
    frontend?.kill();
    process.exit(code ?? 1);
  }
});

try {
  await waitForBackendReady({
    url: 'http://127.0.0.1:5000/api/ping',
    timeoutMs: 30000,
    backend,
  });
} catch (error) {
  backend.kill();
  throw error;
}

frontend = start(process.execPath, ['node_modules/vite/bin/vite.js'], 'vite');

frontend.on('exit', (code) => {
  if (code !== 0) {
    backend.kill();
    process.exit(code ?? 1);
  }
});

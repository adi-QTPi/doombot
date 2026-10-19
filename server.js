'use strict';

const http = require('node:http');
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const { WebSocketServer } = require('ws');
const pty = require('node-pty');
const { spawn } = require('node:child_process');

const PORT = Number(process.env.PORT || 8004);
const HOST = process.env.HOST || '127.0.0.1';
const SHELL_BIN = process.env.SHELL_BIN || process.env.SHELL || '/bin/bash';
const CMD_TIMEOUT_MS = Number(process.env.CMD_TIMEOUT_MS || 30_000);
const MAX_STREAM_BYTES = Number(process.env.MAX_STREAM_BYTES || 1_000_000);
const SESSION_IDLE_MS = Number(process.env.SESSION_IDLE_MS || 600_000);
const REPLAY_BYTES = Number(process.env.REPLAY_BYTES || 200_000);

const app = express();

app.use(express.json({ limit: '64kb' }));
app.use('/vendor/xterm', express.static(path.join(__dirname, 'node_modules', '@xterm', 'xterm')));
app.use('/vendor/addon-fit', express.static(path.join(__dirname, 'node_modules', '@xterm', 'addon-fit')));
app.use(express.static(path.join(__dirname, 'public')));

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

const sessions = new Map();

function broadcast(session, message) {
  const payload = JSON.stringify(message);
  for (const ws of session.clients) {
    if (ws.readyState === ws.OPEN) ws.send(payload);
  }
}

function createSession(cols, rows) {
  const id = crypto.randomUUID();
  const session = {
    id,
    cols: clamp(cols, 2, 500),
    rows: clamp(rows, 2, 200),
    buffer: [],
    bufferBytes: 0,
    clients: new Set(),
    reapTimer: null,
    alive: true,
  };

  session.shell = pty.spawn(SHELL_BIN, ['-l'], {
    name: 'xterm-256color',
    cols: session.cols,
    rows: session.rows,
    cwd: process.cwd(),
    env: process.env,
  });

  session.shell.onData((data) => {
    const chunk = Buffer.from(data, 'utf8');
    session.buffer.push(chunk);
    session.bufferBytes += chunk.length;
    while (session.bufferBytes > REPLAY_BYTES && session.buffer.length > 1) {
      session.bufferBytes -= session.buffer.shift().length;
    }
    broadcast(session, { t: 'o', d: data });
  });

  session.shell.onExit(({ exitCode }) => {
    session.alive = false;
    if (session.reapTimer) clearTimeout(session.reapTimer);
    broadcast(session, { t: 'x', code: exitCode });
    for (const ws of session.clients) ws.close();
    session.clients.clear();
    sessions.delete(id);
  });

  sessions.set(id, session);
  return session;
}

function attach(session, ws) {
  if (session.reapTimer) {
    clearTimeout(session.reapTimer);
    session.reapTimer = null;
  }

  session.clients.add(ws);

  if (session.bufferBytes > 0) {
    ws.send(JSON.stringify({ t: 'o', d: Buffer.concat(session.buffer).toString('utf8') }));
  }
  ws.send(JSON.stringify({ t: 's', id: session.id }));
}

function detach(session, ws) {
  session.clients.delete(ws);

  if (session.clients.size === 0 && session.alive && !session.reapTimer) {
    session.reapTimer = setTimeout(() => killSession(session), SESSION_IDLE_MS);
  }
}

function killSession(session) {
  if (session.reapTimer) {
    clearTimeout(session.reapTimer);
    session.reapTimer = null;
  }
  for (const ws of session.clients) ws.close();
  session.clients.clear();
  sessions.delete(session.id);
  if (session.alive) session.shell.kill();
}

function runCommand(cmd) {
  return new Promise((resolve) => {
    const child = spawn(SHELL_BIN, ['-c', cmd], {
      cwd: process.cwd(),
      env: process.env,
    });

    const buffers = { stdout: [], stderr: [] };
    const sizes = { stdout: 0, stderr: 0 };
    let truncated = false;
    let timedOut = false;

    const makeHandler = (key) => (chunk) => {
      if (sizes[key] >= MAX_STREAM_BYTES) {
        truncated = true;
        return;
      }
      buffers[key].push(chunk);
      sizes[key] += chunk.length;
    };

    child.stdout.on('data', makeHandler('stdout'));
    child.stderr.on('data', makeHandler('stderr'));

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, CMD_TIMEOUT_MS);

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({
        stdout: '',
        stderr: `failed to start command: ${err.message}`,
        code: null,
        signal: null,
        timedOut: false,
        truncated: false,
      });
    });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(buffers.stdout).toString('utf8'),
        stderr: Buffer.concat(buffers.stderr).toString('utf8'),
        code: timedOut ? null : code,
        signal: signal || null,
        timedOut,
        truncated,
      });
    });
  });
}

app.post('/api/exec', async (req, res) => {
  const cmd = req.body && typeof req.body.cmd === 'string' ? req.body.cmd : '';

  if (!cmd.trim()) {
    res.status(400).json({ error: 'A command is required.' });
    return;
  }

  const result = await runCommand(cmd);
  res.json({ cmd, ...result });
});

app.get('/api/env', (_req, res) => {
  res.json({ cwd: process.cwd(), shell: SHELL_BIN, timeoutMs: CMD_TIMEOUT_MS, idleMs: SESSION_IDLE_MS });
});

app.get('/api/sessions', (_req, res) => {
  res.json(
    [...sessions.values()].map((s) => ({
      id: s.id,
      cols: s.cols,
      rows: s.rows,
      attached: s.clients.size > 0,
      clients: s.clients.size,
    })),
  );
});

app.delete('/api/sessions/:id', (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) {
    res.status(404).json({ error: 'no such session' });
    return;
  }
  killSession(session);
  res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const requested = url.searchParams.get('session');
  const cols = clamp(url.searchParams.get('cols') || 80, 2, 500);
  const rows = clamp(url.searchParams.get('rows') || 24, 2, 200);

  let session = requested ? sessions.get(requested) : null;

  if (session && session.alive) {
    session.cols = cols;
    session.rows = rows;
    session.shell.resize(cols, rows);
  } else {
    session = createSession(cols, rows);
  }

  attach(session, ws);

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (!session.alive) return;

    if (msg.t === 'i' && typeof msg.d === 'string') {
      session.shell.write(msg.d);
    } else if (msg.t === 'r') {
      const c = clamp(msg.cols, 2, 500);
      const r = clamp(msg.rows, 2, 200);
      if (c === session.cols && r === session.rows) return;
      session.cols = c;
      session.rows = r;
      session.shell.resize(c, r);
    }
  });

  ws.on('close', () => detach(session, ws));
  ws.on('error', () => detach(session, ws));
});

function shutdown() {
  for (const session of [...sessions.values()]) killSession(session);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

server.listen(PORT, HOST, () => {
  console.log(`web terminal listening on http://${HOST}:${PORT}`);
  console.log(`shell: ${SHELL_BIN}  cwd: ${process.cwd()}`);
  console.log(`idle sessions are reaped after ${Math.round(SESSION_IDLE_MS / 1000)}s`);
  if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
    console.warn(`WARNING: bound to ${HOST}. This is an interactive shell exposed to the network. Do not do this without auth in front.`);
  }
});

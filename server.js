'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const { WebSocketServer } = require('ws');
const pty = require('node-pty');
const { spawn } = require('node:child_process');

const PORT = Number(process.env.PORT || 8004);
const HOST = process.env.HOST || '127.0.0.1';
const CMD_TIMEOUT_MS = Number(process.env.CMD_TIMEOUT_MS || 30_000);
const MAX_STREAM_BYTES = Number(process.env.MAX_STREAM_BYTES || 1_000_000);
const SESSION_IDLE_MS = Number(process.env.SESSION_IDLE_MS || 600_000);
const REPLAY_BYTES = Number(process.env.REPLAY_BYTES || 200_000);
const AUTH_USER = process.env.AUTH_USER || '';
const AUTH_PASS = process.env.AUTH_PASS || '';
const AUTH_ENABLED = Boolean(AUTH_USER && AUTH_PASS);
const AUTH_TTL_MS = Number(process.env.AUTH_TTL_MS || 12 * 60 * 60 * 1000);
const LOGIN_MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 10);
const LOGIN_WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS || 5 * 60 * 1000);
const AUTH_COOKIE = 'webshell_token';

function isExecutableFile(candidate) {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

// Keep the runtime footprint small: bash is not guaranteed to exist (alpine and
// other slim images ship busybox sh only), so pick the first shell that is
// actually present instead of hardcoding /bin/bash. node-pty otherwise dies
// with "execvp(3) failed.: No such file or directory" when spawning.
function resolveShell() {
  const candidates = [process.env.SHELL_BIN, process.env.SHELL, '/bin/bash', '/bin/sh'].filter(Boolean);

  for (const candidate of candidates) {
    if (candidate.includes(path.sep)) {
      if (isExecutableFile(candidate)) return candidate;
      continue;
    }
    for (const dir of (process.env.PATH || '').split(path.delimiter)) {
      if (dir && isExecutableFile(path.join(dir, candidate))) return candidate;
    }
  }

  return 'sh';
}

const SHELL_BIN = resolveShell();

const app = express();

app.use(express.json({ limit: '64kb' }));

function parseCookies(header) {
  const out = {};
  if (!header) return out;

  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      out[name] = part.slice(eq + 1).trim();
    }
  }

  return out;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

const authTokens = new Map();

function issueToken() {
  const token = crypto.randomBytes(32).toString('base64url');
  authTokens.set(token, Date.now() + AUTH_TTL_MS);
  return token;
}

function tokenValid(token) {
  const expires = authTokens.get(token);
  if (!expires) return false;
  if (expires <= Date.now()) {
    authTokens.delete(token);
    return false;
  }
  return true;
}

function isAuthed(req) {
  if (!AUTH_ENABLED) return true;
  return tokenValid(parseCookies(req.headers.cookie)[AUTH_COOKIE]);
}

function setAuthCookie(req, res, value) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const attrs = [`${AUTH_COOKIE}=${value}`, 'HttpOnly', 'SameSite=Lax', 'Path=/'];
  if (secure) attrs.push('Secure');
  if (!value) attrs.push('Max-Age=0');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

// Throttle guessing so the login form is not a free brute-force oracle for the
// password sitting in front of a shell.
const loginFailures = new Map();

function loginBlocked(ip) {
  const entry = loginFailures.get(ip);
  if (!entry) return false;
  if (entry.resetAt <= Date.now()) {
    loginFailures.delete(ip);
    return false;
  }
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}

function recordLoginFailure(ip) {
  const now = Date.now();
  const entry = loginFailures.get(ip);
  if (!entry || entry.resetAt <= now) {
    loginFailures.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    return;
  }
  entry.count += 1;
}

// Only ever bounce back to a path on this host, never to an attacker-supplied
// absolute URL.
function safeNext(value) {
  if (typeof value !== 'string') return '/';
  if (!value.startsWith('/') || value.startsWith('//')) return '/';
  return value;
}

function clientIp(req) {
  return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}

app.get('/login', (req, res) => {
  if (AUTH_ENABLED && isAuthed(req)) {
    res.redirect('/');
    return;
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', (req, res) => {
  if (!AUTH_ENABLED) {
    res.json({ ok: true, next: '/' });
    return;
  }

  const ip = clientIp(req);
  if (loginBlocked(ip)) {
    res.status(429).json({ error: 'too many attempts, wait a few minutes' });
    return;
  }

  const body = req.body || {};
  const username = typeof body.username === 'string' ? body.username : '';
  const password = typeof body.password === 'string' ? body.password : '';

  const userOk = safeEqual(username, AUTH_USER);
  const passOk = safeEqual(password, AUTH_PASS);

  if (!userOk || !passOk) {
    recordLoginFailure(ip);
    res.status(401).json({ error: 'invalid username or password' });
    return;
  }

  loginFailures.delete(ip);
  setAuthCookie(req, res, issueToken());
  res.json({ ok: true, next: safeNext(body.next) });
});

app.post('/api/logout', (req, res) => {
  const token = parseCookies(req.headers.cookie)[AUTH_COOKIE];
  if (token) authTokens.delete(token);
  setAuthCookie(req, res, '');
  res.json({ ok: true });
});

const PUBLIC_PATHS = new Set(['/login', '/login.html', '/api/login', '/api/logout']);

// Everything below this gate is the shell: the terminal page, its APIs and the
// websocket all need a session cookie.
app.use((req, res, next) => {
  if (!AUTH_ENABLED || PUBLIC_PATHS.has(req.path) || req.path.startsWith('/vendor/')) {
    next();
    return;
  }

  if (isAuthed(req)) {
    next();
    return;
  }

  if (req.path.startsWith('/api/')) {
    res.status(401).json({ error: 'authentication required' });
    return;
  }

  res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
});

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
  if (AUTH_ENABLED && !isAuthed(req)) {
    ws.close(1008, 'authentication required');
    return;
  }

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
  if (AUTH_ENABLED) {
    console.log(`auth: enabled, user "${AUTH_USER}", sessions last ${Math.round(AUTH_TTL_MS / 3_600_000)}h, login at /login`);
  } else {
    console.warn('WARNING: AUTH_USER/AUTH_PASS are not set. Set both to put the login page in front of the terminal.');
  }
  if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
    console.warn(`WARNING: bound to ${HOST}. This is an interactive shell exposed to the network. Do not do this without auth in front.`);
  }
});

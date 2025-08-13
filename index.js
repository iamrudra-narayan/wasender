// index.js
'use strict';

const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const dotenv = require('dotenv');
const swaggerUi = require('swagger-ui-express');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

dotenv.config();

/* ---------- Config ---------- */
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const NODE_ENV = process.env.NODE_ENV || 'development';

const API_PASSWORD = process.env.API_PASSWORD || process.env.API_KEY || process.env.PASSWORD;
const QR_USERNAME = process.env.QR_USERNAME || 'admin';
const QR_PASSWORD = process.env.QR_PASSWORD || 'admin123';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-now-in-prod';
const AUTH_COOKIE_NAME = 'qr_auth';
const hours = Number(process.env.AUTH_COOKIE_MAX_AGE_HRS) || 24;
const AUTH_COOKIE_MAX_AGE_MS = hours * 60 * 60 * 1000;

if (!API_PASSWORD) {
  console.warn('WARNING: API_PASSWORD is not set. Set API_PASSWORD in your .env for API protection.');
}

/* ---------- App ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: false, // for inline styles in minimal pages
}));
app.use(compression());
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

/* ---------- Rate limits ---------- */
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});
const qrLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

/* ---------- Swagger (Open to all) ---------- */
const swaggerSpec = {
  openapi: '3.0.3',
  info: {
    title: 'WhatsApp Messaging API',
    version: '1.0.0',
    description:
      'Login via QR (UI) then use these APIs. All APIs require a "password" field in JSON body.'
  },
  servers: [{ url: PUBLIC_URL }],
  paths: {
    '/status': {
      post: {
        summary: 'Client status (protected: password in body)',
        tags: ['Utility'],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['password'],
            properties: { password: { type: 'string', example: 'YOUR_API_PASSWORD' } }
          } } }
        },
        responses: {
          200: { description: 'Status' },
          401: { description: 'Unauthorized' }
        }
      }
    },
    '/send-message': {
      post: {
        summary: 'Send a single WhatsApp message (protected: password in body)',
        tags: ['Messaging'],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['password', 'phone_number', 'message'],
            properties: {
              password: { type: 'string', example: 'YOUR_API_PASSWORD' },
              phone_number: { type: 'string', example: '+919999999999' },
              message: { type: 'string', example: 'Hello from API' }
            }
          } } }
        },
        responses: {
          200: { description: 'Message sent' },
          400: { description: 'Validation error' },
          409: { description: 'Client not ready' },
          500: { description: 'Internal error' }
        }
      }
    },
    '/send-bulk': {
      post: {
        summary: 'Send a message to multiple numbers (protected: password in body)',
        tags: ['Messaging'],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['password', 'phone_numbers', 'message'],
            properties: {
              password: { type: 'string', example: 'YOUR_API_PASSWORD' },
              phone_numbers: { type: 'array', items: { type: 'string' }, example: ['+911234567890', '+919876543210'] },
              message: { type: 'string', example: 'Hello everyone!' }
            }
          } } }
        },
        responses: {
          200: { description: 'Bulk response' },
          400: { description: 'Validation error' },
          409: { description: 'Client not ready' },
          500: { description: 'Internal error' }
        }
      }
    }
  }
};

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.get('/docs.json', (req, res) => res.json(swaggerSpec));

/* ---------- WhatsApp Client ---------- */
const client = new Client({
  authStrategy: new LocalAuth({
    // dataPath: './.wwebjs_auth', // uncomment to pin a folder
  }),
});

let lastQr = null;      // raw QR string
let lastQrAt = null;    // timestamp (ms)
let isReady = false;

client.on('qr', (qr) => {
  lastQr = qr;
  lastQrAt = Date.now();
  isReady = false;
  console.log('[WA] New QR generated.');
});

client.on('ready', () => {
  isReady = true;
  console.log('[WA] Client is ready.');
});

client.on('authenticated', () => {
  console.log('[WA] Authenticated.');
});

client.on('disconnected', (reason) => {
  console.warn('[WA] Disconnected:', reason);
  isReady = false;
});

client.on('auth_failure', (msg) => {
  console.error('[WA] Auth failure:', msg);
  isReady = false;
});

client.initialize();

/* ---------- Helpers ---------- */
function verifyPasswordInBody(req, res, next) {
  const provided = req.body?.password;
  if (!API_PASSWORD || provided !== API_PASSWORD) {
    return res.status(401).json({ status: 'error', message: 'Unauthorized. Provide correct "password" in JSON body.' });
  }
  return next();
}

function signQrSession(username) {
  return jwt.sign({ u: username, t: Date.now() }, SESSION_SECRET, { expiresIn: Math.floor(AUTH_COOKIE_MAX_AGE_MS / 1000) });
}

function requireQrSession(req, res, next) {
  const token = req.cookies[AUTH_COOKIE_NAME];
  if (!token) return redirectToLogin(res);
  try {
    jwt.verify(token, SESSION_SECRET);
    return next();
  } catch {
    return redirectToLogin(res);
  }
}

function redirectToLogin(res) {
  res.set('Cache-Control', 'no-store');
  return res.redirect('/qr/login');
}

async function sendWhatsAppMessage(phone, message) {
  const chatId = `${String(phone).replace(/[^\d]/g, '')}@c.us`;
  await client.sendMessage(chatId, message);
}

/* ---------- Health ---------- */
app.get('/healthz', (req, res) => {
  res.json({ ok: true, isReady });
});

/* ---------- APIs (Protected via password in body) ---------- */
app.post('/status', verifyPasswordInBody, (req, res) => {
  const ageSec = lastQrAt ? Math.max(0, Math.round((Date.now() - lastQrAt) / 1000)) : null;
  res.json({ status: 'success', isReady, lastQrAt, lastQrAgeSec: ageSec });
});

app.post('/send-message', verifyPasswordInBody, async (req, res) => {
  try {
    const { phone_number, message } = req.body || {};
    if (!phone_number || !message) {
      return res.status(400).json({ status: 'error', message: 'phone_number and message are required' });
    }
    if (!isReady) {
      return res.status(409).json({ status: 'error', message: 'WhatsApp client not ready. Open the QR portal to login.' });
    }
    await sendWhatsAppMessage(phone_number, message);
    return res.json({ status: 'success', sent_to: phone_number });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/send-bulk', verifyPasswordInBody, async (req, res) => {
  try {
    const { phone_numbers, message } = req.body || {};
    if (!Array.isArray(phone_numbers) || phone_numbers.length === 0 || !message) {
      return res.status(400).json({ status: 'error', message: 'phone_numbers (non-empty array) and message are required' });
    }
    if (!isReady) {
      return res.status(409).json({ status: 'error', message: 'WhatsApp client not ready. Open the QR portal to login.' });
    }
    const sent_to = [];
    const failed_to = [];
    for (const phone of phone_numbers) {
      try {
        await sendWhatsAppMessage(phone, message);
        sent_to.push(phone);
      } catch (e) {
        failed_to.push({ phone, error: e.message });
      }
    }
    return res.json({ status: 'success', sent_to, failed_to });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: 'error', message: err.message });
  }
});

/* ---------- QR Portal (Session Login + UI) ---------- */

// Login page (GET)
app.get('/qr/login', loginLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>QR Portal Login</title>
<style>
:root{--bg:#0b1020;--card:#121933;--muted:#9aa3b2;--accent:#7c3aed;--ok:#16a34a;--warn:#f59e0b;}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(180deg,#0b1020,#0b1020 60%,#10162b);font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#e5e7eb;display:grid;place-items:center;min-height:100vh;padding:24px}
.card{width:100%;max-width:420px;background:var(--card);border:1px solid #1f2a44;border-radius:16px;padding:24px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
h1{margin:0 0 4px;font-size:22px}p{margin:0 0 16px;color:var(--muted);font-size:14px}
label{display:block;margin:12px 0 6px;color:#cfd7e3;font-size:13px}
input{width:100%;padding:12px 14px;border:1px solid #2a3559;background:#0e1531;color:#e5e7eb;border-radius:12px;outline:none}
button{width:100%;padding:12px 14px;margin-top:16px;background:var(--accent);border:none;border-radius:12px;color:#fff;font-weight:600;cursor:pointer}
button:active{transform:translateY(1px)}
small{display:block;margin-top:10px;color:var(--muted)}
.footer{margin-top:14px;text-align:center}
.err{color:#ff6b6b;margin:8px 0 0;min-height:18px}
</style>
</head>
<body>
  <div class="card">
    <h1>KpiX WhatsApp Registration Portal</h1>
    <p>Sign in to access the WhatsApp QR and connection status.</p>
    <form method="POST" action="/qr/login">
      <label>Username</label>
      <input name="username" autocomplete="username" required />
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required />
      <button type="submit">Sign In</button>
    </form>
    <small>Tip: set <code>QR_USERNAME</code> & <code>QR_PASSWORD</code> in <code>.env</code>.</small>
    <div class="footer"><small>v1.0 • Secure QR Portal</small></div>
  </div>
</body>
</html>`);
});

// Parse URL-encoded form for login submit
app.use('/qr/login', express.urlencoded({ extended: false }));

// Login (POST)
app.post('/qr/login', loginLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');
  const { username, password } = req.body || {};
  if (username === QR_USERNAME && password === QR_PASSWORD) {
    const token = signQrSession(username);
    res.cookie(AUTH_COOKIE_NAME, token, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: AUTH_COOKIE_MAX_AGE_MS,
      signed: false,
    });
    return res.redirect('/qr');
  }
  return res.status(401).type('html').send('<p style="font-family:system-ui;color:#d33">Invalid credentials. <a href="/qr/login">Try again</a></p>');
});

// Logout
app.post('/qr/logout', requireQrSession, (req, res) => {
  res.clearCookie(AUTH_COOKIE_NAME);
  res.redirect('/qr/login');
});

// QR page (requires session)
app.get('/qr', qrLimiter, requireQrSession, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>KpiX WhatsApp Login</title>
<style>
:root{--bg:#0b1020;--card:#121933;--muted:#9aa3b2;--ok:#16a34a;--warn:#f59e0b;--bad:#ef4444}
*{box-sizing:border-box}body{margin:0;background:#0b1020;font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#e5e7eb;min-height:100vh}
.wrap{max-width:860px;margin:0 auto;padding:24px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
h1{font-size:22px;margin:0}
small{color:var(--muted)}
.card{border:1px solid #1f2a44;background:var(--card);border-radius:16px;padding:16px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media (max-width:800px){.grid{grid-template-columns:1fr}}
img{width:100%;height:auto;border-radius:12px;background:#0e1531}
.badge{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:600;font-size:12px}
.badge.ok{background:#102a1a;color:#8ef0a1;border:1px solid #1d5a31}
.badge.warn{background:#2a1d10;color:#ffd18a;border:1px solid #5a3a1d}
.badge.bad{background:#2a1010;color:#ffb4b4;border:1px solid #5a1d1d}
.btn{appearance:none;border:1px solid #2b3b67;background:#101938;color:#e5e7eb;border-radius:10px;padding:8px 12px;cursor:pointer}
.btn:active{transform:translateY(1px)}
</style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div>
        <h1>WhatsApp Device Link</h1>
        <small>Scan the QR code below with WhatsApp &rarr; Linked devices.</small>
      </div>
      <form method="POST" action="/qr/logout"><button class="btn" type="submit">Logout</button></form>
    </div>

    <div class="grid">
      <div class="card">
        <h3 style="margin:0 0 8px">QR Code</h3>
        <img id="qrImg" alt="QR Code" src="/qr-image.png" />
        <small id="qrMeta">Loading…</small>
      </div>
      <div class="card">
        <h3 style="margin:0 0 8px">Status</h3>
        <div id="stBadge" class="badge warn">Checking…</div>
        <div style="margin-top:12px">
          <small>QR auto-refreshes every 5s while not connected.</small><br/>
          <small>If connected, this page will show status.</small>
        </div>
      </div>
    </div>
  </div>

<script>
async function refresh(){
  try{
    const r = await fetch('/qr-status', { cache:'no-store' });
    const s = await r.json();
    const img = document.getElementById('qrImg');
    const meta = document.getElementById('qrMeta');
    const badge = document.getElementById('stBadge');

    if(s.isReady){
      badge.className = 'badge ok';
      badge.textContent = 'Connected';
      meta.textContent = 'Client connected to WhatsApp.';
    }else{
      badge.className = 'badge warn';
      badge.textContent = 'Waiting for scan';
      meta.textContent = s.lastQrAt ? ('QR age: '+s.lastQrAgeSec+'s') : 'Waiting for QR…';
      img.src = '/qr-image.png?t=' + Date.now();
    }
  }catch(e){
    const badge = document.getElementById('stBadge');
    badge.className = 'badge bad';
    badge.textContent = 'Error';
  }
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`);
});

// QR image (requires session)
app.get('/qr-image.png', qrLimiter, requireQrSession, async (req, res) => {
  try {
    if (!lastQr) {
      res.set('Cache-Control', 'no-store');
      return res.status(404).json({ status: 'error', message: 'No QR available yet. Please wait…' });
    }
    const buffer = await qrcode.toBuffer(lastQr);
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.send(buffer);
  } catch (err) {
    return res.status(500).json({ status: 'error', message: 'Failed to generate QR image' });
  }
});

// QR status API for the portal (requires session)
app.get('/qr-status', qrLimiter, requireQrSession, (req, res) => {
  const ageSec = lastQrAt ? Math.max(0, Math.round((Date.now() - lastQrAt) / 1000)) : null;
  res.set('Cache-Control', 'no-store');
  res.json({ isReady, lastQrAt, lastQrAgeSec: ageSec });
});

/* ---------- Error handling ---------- */
app.use((req, res) => {
  res.status(404).json({ status: 'error', message: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error('[UNCAUGHT]', err);
  res.status(500).json({ status: 'error', message: 'Internal Server Error' });
});

/* ---------- Graceful shutdown ---------- */
function shutdown() {
  console.log('Shutting down...');
  try { client.destroy(); } catch {}
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

/* ---------- Start ---------- */
app.listen(PORT, HOST, () => {
  console.log(`Server running at ${PUBLIC_URL}`);
  console.log(`Swagger docs: ${PUBLIC_URL}/docs`);
  console.log(`QR Portal: ${PUBLIC_URL}/qr/login`);
});
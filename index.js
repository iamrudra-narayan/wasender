// index.js
'use strict';

const express = require('express');
const { Client, LocalAuth, RemoteAuth } = require('whatsapp-web.js');
const { MongoStore } = require('wwebjs-mongo');
const mongoose = require('mongoose');
const qrcode = require('qrcode');
const dotenv = require('dotenv');
const swaggerUi = require('swagger-ui-express');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { randomInt } = require('crypto');
const cors = require('cors');

dotenv.config();

/* ---------- Config (kept same) ---------- */
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const NODE_ENV = process.env.NODE_ENV || 'development';

const API_PASSWORD = process.env.API_PASSWORD || process.env.API_KEY || process.env.PASSWORD || '';
const QR_USERNAME = process.env.QR_USERNAME || 'admin';
const QR_PASSWORD = process.env.QR_PASSWORD || 'admin123';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-now-in-prod';
const AUTH_COOKIE_NAME = 'qr_auth';
const hours = Number(process.env.AUTH_COOKIE_MAX_AGE_HRS) || 24;
const AUTH_COOKIE_MAX_AGE_MS = hours * 60 * 60 * 1000;

const MONGO_URI = process.env.MONGO_URI || '';

// Where to store whatsapp-web.js auth/cache for local
const WWEBJS_DATA_DIR = process.env.WWEBJS_DATA_DIR || path.join(__dirname, '.wwebjs_data');
const SESSION_DIR = path.join(WWEBJS_DATA_DIR, 'auth');  // LocalAuth dataPath
const CACHE_DIR = path.join(WWEBJS_DATA_DIR, 'cache');   // optional: for any cache you want to keep separate

if (!API_PASSWORD) {
  console.warn('WARNING: API_PASSWORD is not set. Set API_PASSWORD in your .env for API protection.');
}
if (!MONGO_URI) {
  console.warn('NOTICE: MONGO_URI not set — running in LocalAuth (disk) mode. For Render/no-disk set MONGO_URI to use RemoteAuth.');
}

// ensure local dirs exist (harmless if using remote)
try { fs.mkdirSync(SESSION_DIR, { recursive: true }); } catch {}
try { fs.mkdirSync(CACHE_DIR, { recursive: true }); } catch {}

/* ---------- Bulk config (tune for production) ---------- */
const BULK_CONCURRENCY = Number(process.env.BULK_CONCURRENCY) || 2; // safe default
const BULK_DELAY_MS = Number(process.env.BULK_DELAY_MS) || 1500; // ms delay between sends per worker
const BULK_RETRIES = Number(process.env.BULK_RETRIES) || 3;
const BULK_RETRY_BASE_MS = Number(process.env.BULK_RETRY_BASE_MS) || 800;
const BULK_JITTER_MS = Number(process.env.BULK_JITTER_MS) || 300;

/* ---------- App ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET','POST'],
}));
app.use(compression());
app.use(express.json({ limit: '512kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

/* ---------- Rate limits ---------- */
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});
const qrLimiter = rateLimit({
  windowMs: 60 * 1000,
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
        responses: { 200: { description: 'Status' }, 401: { description: 'Unauthorized' } }
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

/* ---------- Globals for auth/store + WA ---------- */
let store = null;       // MongoStore (when using RemoteAuth)
let client = null;      // whatsapp client
let lastQr = null;
let lastQrAt = null;
let isReady = false;
let authMode = 'local'; // 'local' or 'remote'
let initializingClient = false;

/* ---------- Helpers ---------- */
function verifyPasswordInBody(req, res, next) {
  const provided = req.body?.password;
  if (!API_PASSWORD || provided !== API_PASSWORD) {
    return res.status(401).json({ status: 'error', message: 'Unauthorized. Provide correct "password" in JSON body.' });
  }
  return next();
}

function signQrSession(username) {
  return jwt.sign(
    { u: username, t: Date.now() },
    SESSION_SECRET,
    { expiresIn: Math.floor(AUTH_COOKIE_MAX_AGE_MS / 1000) }
  );
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

async function rimraf(dir) {
  try { await fsp.rm(dir, { recursive: true, force: true }); } catch (e) {}
  try { await fsp.mkdir(dir, { recursive: true }); } catch (e) {}
}

/* ---------- Init mongoose + store (if MONGO_URI present) ---------- */
async function initMongooseStoreIfNeeded() {
  if (!MONGO_URI) {
    authMode = 'local';
    console.log('[AUTH] No MONGO_URI — using LocalAuth (disk) mode');
    return;
  }

  // connect mongoose (needed for wwebjs-mongo MongoStore)
  authMode = 'remote';
  console.log('[AUTH] MONGO_URI found — using RemoteAuth (MongoStore) mode');

  mongoose.set('strictQuery', false);
  // small retry loop for transient connect issues
  const maxAttempts = 5;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await mongoose.connect(MONGO_URI, {
        // Mongoose v6+ defaults are fine
      });
      console.log('✅ Mongoose connected');
      break;
    } catch (err) {
      console.warn(`[MONGO] connect attempt ${attempt} failed:`, err && err.message ? err.message : err);
      if (attempt === maxAttempts) throw err;
      await new Promise(r => setTimeout(r, 1500 * attempt));
    }
  }

  // Create the MongoStore using mongoose instance (this is what's required)
  store = new MongoStore({ mongoose });
  console.log('✅ MongoStore created and ready');
}

/* ---------- Build WhatsApp client (chooses LocalAuth or RemoteAuth) ---------- */
function buildClient() {
  const authStrategy = (authMode === 'remote' && store)
    ? new RemoteAuth({ store, backupSyncIntervalMs: 300000 })
    : new LocalAuth({ dataPath: SESSION_DIR });

  const c = new Client({
    authStrategy,
    puppeteer: {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-gpu',
        '--window-size=1280,800'
      ],
    },
    takeoverOnConflict: true,
  });

  c.on('qr', (qr) => {
    lastQr = qr;
    lastQrAt = Date.now();
    isReady = false;
    console.log('[WA] New QR generated.');
  });

  c.on('ready', () => {
    isReady = true;
    lastQr = null;
    lastQrAt = null;
    console.log('[WA] Client is ready.');
  });

  c.on('authenticated', () => {
    console.log('[WA] Authenticated.');
    lastQr = null;
    lastQrAt = null;
  });

  c.on('auth_failure', (msg) => {
    console.error('[WA] Auth failure:', msg);
    isReady = false;
    // Rebuild after short backoff
    setTimeout(() => tryRebuildClient('[auth_failure]').catch(e => console.error('[WA] rebuild after auth_failure failed', e)), 2000);
  });

  c.on('disconnected', async (reason) => {
    console.warn('[WA] Disconnected:', reason);
    isReady = false;
    // ensure current instance destroyed then rebuild
    try { await c.destroy(); } catch (e) { /* ignore */ }
    setTimeout(() => tryRebuildClient('[disconnected]').catch(e => console.error('[WA] rebuild after disconnected failed', e)), 2000);
  });

  c.on('change_state', (state) => {
    console.log('[WA] State:', state);
  });

  return c;
}

/* ---------- Safely rebuild client ---------- */
async function tryRebuildClient(reason = '') {
  if (initializingClient) {
    console.log('[WA] Already initializing client, skipping rebuild request:', reason);
    return;
  }
  initializingClient = true;
  console.log(`[WA] Rebuilding client ${reason}`);

  // cleanup previous
  try {
    if (client && client.destroy) {
      try { await client.destroy(); } catch (ignored) {}
    }
  } catch (e) {
    // ignore
  }

  // if remote mode ensure store present
  if (authMode === 'remote' && !store) {
    console.error('[WA] Cannot build remote client because store is not ready');
    initializingClient = false;
    throw new Error('Mongo store not ready');
  }

  client = buildClient();

  try {
    await client.initialize();
    console.log('[WA] New client initialized.');
  } catch (err) {
    console.error('[WA] Error initializing client:', err && err.message ? err.message : err);
    initializingClient = false;
    throw err;
  }

  initializingClient = false;
}

/* ---------- Utility sleep ---------- */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ---------- Robust send function with retries + exponential backoff + jitter ---------- */
async function sendWithRetry(phone, message, retries = BULK_RETRIES) {
  if (!phone) return { success: false, error: 'invalid_phone' };
  const chatId = `${String(phone).replace(/[^\d]/g, '')}@c.us`;
  let attempt = 0;

  while (attempt <= retries) {
    if (!isReady || !client) {
      // wait briefly for client readiness
      let waited = 0;
      while (!isReady && waited < 60) { // wait up to 60 seconds
        await sleep(1000);
        waited++;
      }
      if (!isReady) return { success: false, error: 'client_not_ready' };
    }

    try {
      // sendMessage is awaited to ensure it's completed before next send
      await client.sendMessage(chatId, message);
      return { success: true };
    } catch (err) {
      attempt++;
      const msg = err && err.message ? err.message : String(err);
      console.warn(`[SEND] attempt ${attempt}/${retries} failed for ${phone}: ${msg}`);

      if (attempt > retries) {
        return { success: false, error: msg };
      }

      // backoff
      const base = BULK_RETRY_BASE_MS * Math.pow(2, attempt - 1);
      const jitter = randomInt(0, BULK_JITTER_MS + 1);
      const waitMs = base + jitter;
      await sleep(waitMs);

      // loop and retry
    }
  }

  return { success: false, error: 'unknown' };
}

/* ---------- Health / keepalive ---------- */
app.get('/healthz', (req, res) => res.json({ ok: true, isReady }));
setInterval(() => console.log('[KEEPALIVE] tick'), 5 * 60 * 1000);

/* ---------- APIs (protected) - kept exactly as your original ---------- */
app.post('/status', verifyPasswordInBody, (req, res) => {
  const ageSec = lastQrAt ? Math.max(0, Math.round((Date.now() - lastQrAt) / 1000)) : null;
  res.json({ status: 'success', isReady, lastQrAt, lastQrAgeSec: ageSec });
});

app.post('/send-message', verifyPasswordInBody, async (req, res) => {
  try {
    const { phone_number, message } = req.body || {};
    if (!phone_number || !message) return res.status(400).json({ status: 'error', message: 'phone_number and message are required' });
    if (!isReady) return res.status(409).json({ status: 'error', message: 'WhatsApp client not ready. Open the QR portal to login.' });

    const r = await sendWithRetry(phone_number, message, BULK_RETRIES);
    if (r.success) return res.json({ status: 'success', sent_to: phone_number });
    return res.status(500).json({ status: 'error', message: r.error || 'failed to send' });

  } catch (err) {
    console.error('[SEND]', err && err.message ? err.message : err);
    return res.status(500).json({ status: 'error', message: err.message || String(err) });
  }
});

// app.post('/send-bulk', verifyPasswordInBody, async (req, res) => {
//   try {
//     const { phone_numbers, message, delay_ms = 4000 } = req.body || {};
//     if (!Array.isArray(phone_numbers) || phone_numbers.length === 0 || !message) {
//       return res.status(400).json({ status: 'error', message: 'phone_numbers (non-empty array) and message are required' });
//     }
//     if (!isReady) {
//       return res.status(409).json({ status: 'error', message: 'WhatsApp client not ready. Open the QR portal to login.' });
//     }

//     const sent_to = [];
//     const failed_to = [];

//     // Helper to wait between messages
//     const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

//     for (const phone of phone_numbers) {
//       try {
//         await sendWhatsAppMessage(phone, message); // must be await to ensure sequential sending
//         sent_to.push(phone);
//         console.log(`[BULK] Sent to ${phone}`);
//       } catch (e) {
//         failed_to.push({ phone, error: e.message || String(e) });
//         console.error(`[BULK ERROR] ${phone}: ${e.message || e}`);
//       }
//       await wait(delay_ms); // delay to avoid rate limiting and disconnect
//     }

//     return res.json({ 
//       status: 'success', 
//       sent_to, 
//       failed_to, 
//       delay_per_message_ms: delay_ms 
//     });

//   } catch (err) {
//     console.error('[SENDBULK]', err && err.message ? err.message : err);
//     return res.status(500).json({ status: 'error', message: err.message || String(err) });
//   }
// });
app.post('/send-bulk', verifyPasswordInBody, async (req, res) => {
  try {
    const { phone_numbers, message, delay_ms } = req.body || {};
    const baseDelay = typeof delay_ms === 'number' ? Math.max(5000, delay_ms) : Math.max(BULK_DELAY_MS, 5000); // Minimum 5 seconds

    if (!Array.isArray(phone_numbers) || phone_numbers.length === 0 || !message) {
      return res.status(400).json({ status: 'error', message: 'phone_numbers (array) and message are required' });
    }

    if (!isReady) {
      return res.status(409).json({ status: 'error', message: 'WhatsApp client not ready. Open the QR portal to login.' });
    }

    // Limit batch size to prevent disconnection
    const MAX_BATCH_SIZE = 10;
    if (phone_numbers.length > MAX_BATCH_SIZE) {
      return res.status(400).json({ 
        status: 'error', 
        message: `Batch size too large. Maximum ${MAX_BATCH_SIZE} numbers allowed per request. Split into smaller batches.` 
      });
    }

    console.log(`[SENDBULK] Starting bulk send: count=${phone_numbers.length} delay_ms=${baseDelay}`);

    // Use sequential processing instead of concurrent to avoid disconnection
    const result = await sendBulkSequential(phone_numbers, message, baseDelay);

    console.log('[SENDBULK] Finished bulk send', { 
      sent: result.sent_to.length, 
      failed: result.failed_to.length 
    });

    return res.json({
      status: 'success',
      sent_to: result.sent_to,
      failed_to: result.failed_to,
      total_attempted: phone_numbers.length,
      delay_base_ms: baseDelay,
      warning: phone_numbers.length > 5 ? 'Large batches may cause WhatsApp to disconnect. Consider smaller batches.' : null
    });

  } catch (err) {
    console.error('[SEND-BULK]', err && err.stack ? err.stack : err);
    return res.status(500).json({ 
      status: 'error', 
      message: err && err.message ? err.message : String(err) 
    });
  }
});

// Sequential bulk sender to avoid overwhelming WhatsApp
async function sendBulkSequential(phoneNumbers, message, baseDelay) {
  const sent_to = [];
  const failed_to = [];
  
  for (let i = 0; i < phoneNumbers.length; i++) {
    const phoneNumber = phoneNumbers[i];
    
    try {
      // Check if client is still ready before each send
      if (!isReady) {
        console.log(`[SENDBULK] Client disconnected at number ${i + 1}/${phoneNumbers.length}`);
        // Add remaining numbers to failed list
        for (let j = i; j < phoneNumbers.length; j++) {
          failed_to.push({
            phone: phoneNumbers[j],
            error: 'WhatsApp client disconnected during bulk send'
          });
        }
        break;
      }

      console.log(`[SENDBULK] Sending to ${phoneNumber} (${i + 1}/${phoneNumbers.length})`);
      
      // Add random variation to delay to appear more human-like
      const randomDelay = baseDelay + Math.random() * 2000; // Add 0-2 seconds variation
      
      if (i > 0) {
        console.log(`[SENDBULK] Waiting ${Math.round(randomDelay)}ms before next send...`);
        await new Promise(resolve => setTimeout(resolve, randomDelay));
      }

      // Send message with retry logic
      const success = await sendMessageWithRetry(phoneNumber, message, 2);
      
      if (success) {
        sent_to.push(phoneNumber);
        console.log(`[SENDBULK] ✓ Sent to ${phoneNumber}`);
      } else {
        failed_to.push({
          phone: phoneNumber,
          error: 'Failed after retries'
        });
        console.log(`[SENDBULK] ✗ Failed to send to ${phoneNumber}`);
      }

    } catch (error) {
      console.error(`[SENDBULK] Error sending to ${phoneNumber}:`, error.message);
      failed_to.push({
        phone: phoneNumber,
        error: error.message
      });
    }
  }

  return { sent_to, failed_to };
}

// Enhanced message sender with connection checking
async function sendMessageWithRetry(phoneNumber, message, maxRetries = 2) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      // Check connection before attempting
      if (!client || !isReady) {
        throw new Error('WhatsApp client not ready');
      }

      // Format phone number (adjust based on your formatting logic)
      const formattedNumber = formatPhoneNumber(phoneNumber);
      
      // Send message
      await client.sendMessage(formattedNumber, message);
      
      return true; // Success
      
    } catch (error) {
      console.log(`[RETRY] Attempt ${attempt}/${maxRetries} failed for ${phoneNumber}: ${error.message}`);
      
      if (attempt < maxRetries) {
        // Wait before retry with exponential backoff
        const retryDelay = 3000 * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }
  }
  
  return false; // Failed after all retries
}

// Helper function to format phone number (adjust based on your needs)
function formatPhoneNumber(phoneNumber) {
  // Remove any non-digit characters
  const cleaned = phoneNumber.replace(/\D/g, '');
  
  // Add country code if missing (adjust based on your region)
  let formatted = cleaned;
  if (!formatted.startsWith('91') && formatted.length === 10) {
    formatted = '91' + formatted; // Add India country code
  }
  
  return formatted + '@c.us';
}

// Add connection monitoring
function setupConnectionMonitoring() {
  if (client) {
    client.on('disconnected', (reason) => {
      console.log('[CLIENT] WhatsApp disconnected:', reason);
      isReady = false;
    });

    client.on('ready', () => {
      console.log('[CLIENT] WhatsApp ready');
      isReady = true;
    });

    client.on('auth_failure', (msg) => {
      console.error('[CLIENT] Authentication failure:', msg);
      isReady = false;
    });
  }
}

// Rate limiting endpoint for better control
app.post('/send-bulk-batch', verifyPasswordInBody, async (req, res) => {
  try {
    const { phone_numbers, message, delay_ms, batch_size = 5 } = req.body || {};
    
    if (!Array.isArray(phone_numbers) || phone_numbers.length === 0 || !message) {
      return res.status(400).json({ status: 'error', message: 'phone_numbers (array) and message are required' });
    }

    if (!isReady) {
      return res.status(409).json({ status: 'error', message: 'WhatsApp client not ready' });
    }

    const batches = [];
    for (let i = 0; i < phone_numbers.length; i += batch_size) {
      batches.push(phone_numbers.slice(i, i + batch_size));
    }

    console.log(`[BATCH-SEND] Processing ${batches.length} batches of max ${batch_size} numbers each`);

    const allResults = {
      sent_to: [],
      failed_to: [],
      batches_processed: 0
    };

    for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
      const batch = batches[batchIndex];
      
      console.log(`[BATCH-SEND] Processing batch ${batchIndex + 1}/${batches.length}`);
      
      const batchResult = await sendBulkSequential(batch, message, delay_ms || 10000);
      
      allResults.sent_to.push(...batchResult.sent_to);
      allResults.failed_to.push(...batchResult.failed_to);
      allResults.batches_processed++;

      // Wait between batches to avoid detection
      if (batchIndex < batches.length - 1) {
        const batchDelay = 30000; // 30 seconds between batches
        console.log(`[BATCH-SEND] Waiting ${batchDelay}ms before next batch...`);
        await new Promise(resolve => setTimeout(resolve, batchDelay));
      }
    }

    return res.json({
      status: 'success',
      ...allResults,
      total_attempted: phone_numbers.length
    });

  } catch (err) {
    console.error('[BATCH-SEND]', err);
    return res.status(500).json({ 
      status: 'error', 
      message: err.message 
    });
  }
});

/* ---------- QR Portal + Login UI (kept fully as you provided) ---------- */

// Login page (GET)
app.get('/qr/login', loginLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>KpiX WhatsApp Registration Portal</title>
<style>
:root{--bg:#0b1020;--card:#121933;--muted:#9aa3b2;--accent:#7c3aed;--ok:#16a34a;--warn:#f59e0b;}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(180deg,#0b1020,#0b1020 60%,#10162b);font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#e5e7eb;display:grid;place-items:center;min-height:100vh;padding:24px}
.card{width:100%;max-width:420px;background:var(--card);border:1px solid #1f2a44;border-radius:16px;padding:24px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
h1{margin:0 0 4px;font-size:22px}p{margin:0 0 16px;color:var(--muted);font-size:14px}
label{display:block;margin:12px 0 6px;color:#cfd7e3;font-size:13px}
input{width:100%;padding:12px 14px;border:1px solid #2a3559;background:#0e1531;color:#e5e7eb;border-radius:12px;outline:none}
button{width:100%;padding:12px 14px;margin-top:16px;background:var(--accent);border:none;border-radius:12px;color:#fff;font-weight:600;cursor:pointer}
button:active{transform:translateY(1px)}
small{display:block;margin-top:10px;color:#9aa3b2}
.footer{margin-top:14px;text-align:center}
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
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>KpiX WhatsApp Login</title>
<style>
:root{--bg:#0b1020;--card:#121933;--muted:#9aa3b2;--ok:#16a34a;--warn:#f59e0b;--bad:#ef4444}
*{box-sizing:border-box}body{margin:0;background:#0b1020;font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#e5e7eb;min-height:100vh}
.wrap{max-width:860px;margin:0 auto;padding:24px}
.header{display:flex;gap:12px;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap}
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
.row{display:flex;gap:8px;flex-wrap:wrap}
</style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div>
        <h1>WhatsApp Device Link</h1>
        <small>Scan the QR code below with WhatsApp → Linked devices.</small>
      </div>
      <div class="row">
        <form method="POST" action="/qr/disconnect" onsubmit="return confirm('Disconnect and reset session? You will need to scan a new QR.');">
          <button class="btn" type="submit">Disconnect & Reset</button>
        </form>
        <form method="POST" action="/qr/logout">
          <button class="btn" type="submit">Logout</button>
        </form>
      </div>
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
</body></html>`);
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
    console.error('[QRIMG]', err && err.message ? err.message : err);
    return res.status(500).json({ status: 'error', message: 'Failed to generate QR image' });
  }
});

// QR status API for the portal (requires session)
app.get('/qr-status', qrLimiter, requireQrSession, (req, res) => {
  const ageSec = lastQrAt ? Math.max(0, Math.round((Date.now() - lastQrAt) / 1000)) : null;
  res.set('Cache-Control', 'no-store');
  res.json({ isReady, lastQrAt, lastQrAgeSec: ageSec });
});

// Disconnect & Reset (wipe auth+cache, reinit, show fresh QR)
app.post('/qr/disconnect', qrLimiter, requireQrSession, async (req, res) => {
  try {
    console.log('[RESET] Disconnect requested. Wiping session & cache…');
    try { if (client && client.destroy) await client.destroy(); } catch (e) {}
    await rimraf(SESSION_DIR);
    await rimraf(CACHE_DIR);
    lastQr = null;
    lastQrAt = null;
    isReady = false;
    // rebuild & re-init client so a new QR is produced
    try {
      await tryRebuildClient('[reset]');
    } catch (err) {
      console.error('[RESET] Rebuild failed:', err && err.message ? err.message : err);
    }
    res.redirect('/qr'); // back to portal; it will poll and show the new QR
  } catch (err) {
    console.error('[RESET] Failed:', err && err.message ? err.message : err);
    res.status(500).type('html').send('<p style="font-family:system-ui;color:#d33">Failed to reset. Check server logs.</p>');
  }
});

/* ---------- Error handling ---------- */
app.use((req, res) => res.status(404).json({ status: 'error', message: 'Not Found' }));

app.use((err, req, res, next) => {
  console.error('[UNCAUGHT]', err && err.stack ? err.stack : err);
  res.status(500).json({ status: 'error', message: 'Internal Server Error' });
});

/* ---------- Graceful shutdown ---------- */
async function shutdown() {
  console.log('Shutting down…');
  try { if (client && client.destroy) await client.destroy(); } catch (e) { /* ignore */ }
  try { if (authMode === 'remote') await mongoose.disconnect(); } catch (e) { /* ignore */ }
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

/* ---------- Top-level error handlers ---------- */
process.on('unhandledRejection', (reason, p) => console.error('[UNHANDLED REJECTION]', reason, p));
process.on('uncaughtException', (err) => console.error('[UNCAUGHT EXCEPTION]', err));

/* ---------- Start: init store (if needed) -> init client -> start server ---------- */
(async () => {
  try {
    await initMongooseStoreIfNeeded();
    // ensure client initialization occurs before server becomes usable
    await tryRebuildClient('[startup]');

    const server = app.listen(PORT, HOST, () => {
      console.log(`Server running at ${PUBLIC_URL}`);
      console.log(`Swagger docs: ${PUBLIC_URL}/docs`);
      console.log(`QR Portal: ${PUBLIC_URL}/qr/login`);
      console.log(`[Paths] WWEBJS_DATA_DIR=${WWEBJS_DATA_DIR} (LocalAuth if no MONGO_URI)`);
    });

    server.on('error', (err) => {
      if (err && err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} already in use. Use a different PORT or stop the process using it.`);
      } else {
        console.error('Server error:', err);
      }
    });
  } catch (err) {
    console.error('[STARTUP] Failed to start:', err && err.stack ? err.stack : err);
    process.exit(1);
  }
})();
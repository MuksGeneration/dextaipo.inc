import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import initSqlJs from 'sql.js';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import fs from 'fs';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// ── ADMIN CREDENTIALS (change these in production!) ─────
const ADMIN_USERNAME = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASS || 'Dexta@Admin2026';

// ── UPLOADS DIR ──────────────────────────────────────────
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9.]/g, '_'))
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ── MIDDLEWARE ───────────────────────────────────────────
app.use(cors());
app.use(bodyParser.json({ limit: '15mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '15mb' }));
app.use(express.static(__dirname));
app.use('/uploads', express.static(uploadDir));

// ── DATABASE ──────────────────────────────────────────────
let db = null;
const dbPath = path.join(__dirname, 'dexta.db');

async function initDatabase() {
  const SQL = await initSqlJs();
  
  // Load existing database if it exists
  if (fs.existsSync(dbPath)) {
    const buffer = fs.readFileSync(dbPath);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }
  
  console.log('✓ Connected to SQLite database (sql.js)');
  
  // Create tables
  db.run(`CREATE TABLE IF NOT EXISTS registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT UNIQUE,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT NOT NULL,
    national_id TEXT,
    service TEXT NOT NULL,
    id_front TEXT,
    id_back TEXT,
    face_photo TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS loan_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_number TEXT UNIQUE,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    tin TEXT NOT NULL,
    address TEXT NOT NULL,
    employment TEXT NOT NULL,
    id_front TEXT,
    id_back TEXT,
    passport_photo TEXT,
    otp_verified INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    notes TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS savings_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT UNIQUE,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    account_type TEXT NOT NULL,
    id_front TEXT,
    id_back TEXT,
    otp_verified INTEGER DEFAULT 0,
    interest_rate REAL,
    balance REAL DEFAULT 0,
    status TEXT DEFAULT 'pending',
    notes TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS ipo_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_number TEXT UNIQUE,
    name TEXT,
    email TEXT NOT NULL,
    phone TEXT,
    nid TEXT,
    shares INTEGER NOT NULL,
    amount REAL NOT NULL,
    payment_method TEXT DEFAULT 'pending',
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS ipo_data (
    id INTEGER PRIMARY KEY,
    price REAL DEFAULT 150,
    subscription_percent REAL DEFAULT 68,
    total_shares INTEGER DEFAULT 125000,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Insert default IPO data if not exists
  const ipoRow = db.exec('SELECT * FROM ipo_data WHERE id = 1');
  if (ipoRow.length === 0) {
    db.run('INSERT INTO ipo_data (id, price, subscription_percent, total_shares) VALUES (1, 150, 68, 125000)');
  }
  
  saveDatabase();
}

// Save database to file
function saveDatabase() {
  if (db) {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(dbPath, buffer);
  }
}

// Helper to run queries
function dbRun(sql, params = []) {
  try {
    db.run(sql, params);
    saveDatabase();
    return { changes: db.getRowsModified(), lastID: getLastInsertId() };
  } catch (err) {
    console.error('DB Run Error:', err);
    throw err;
  }
}

function getLastInsertId() {
  const result = db.exec('SELECT last_insert_rowid() as id');
  return result[0]?.values[0]?.[0] || 0;
}

function dbGet(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    if (params.length) stmt.bind(params);
    if (stmt.step()) {
      const result = stmt.getAsObject();
      stmt.free();
      return result;
    }
    stmt.free();
    return null;
  } catch (err) {
    console.error('DB Get Error:', err);
    return null;
  }
}

function dbAll(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    if (params.length) stmt.bind(params);
    const results = [];
    while (stmt.step()) {
      results.push(stmt.getAsObject());
    }
    stmt.free();
    return results;
  } catch (err) {
    console.error('DB All Error:', err);
    return [];
  }
}

// ── ACCOUNT NUMBER GENERATOR ──────────────────────────────
function generateAccountNumber(prefix = 'DXT') {
  const year = new Date().getFullYear().toString().slice(-2);
  const random = Math.floor(100000 + Math.random() * 900000);
  return `${prefix}-${year}-${random}`;
}

// ── ADMIN SESSION TOKENS ──────────────────────────────────
const adminSessions = new Set();
function generateAdminToken() {
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.add(token);
  // Auto-expire after 8 hours
  setTimeout(() => adminSessions.delete(token), 8 * 60 * 60 * 1000);
  return token;
}
function isValidAdminToken(token) {
  return token && adminSessions.has(token);
}
function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!isValidAdminToken(token)) return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  next();
}

// ── StackVerify SMS Config ────────────────────────────────
const STACKVERIFY_API_KEY = process.env.STACKVERIFY_API_KEY || 'sk_live_demo_key';
const STACKVERIFY_BASE_URL = 'https://stackverify.site/api/v1';

async function sendSMSviaStackVerify(phone, message) {
  try {
    const response = await fetch(`${STACKVERIFY_BASE_URL}/sms/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${STACKVERIFY_API_KEY}`
      },
      body: JSON.stringify({ to: phone, message })
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || `StackVerify error: ${response.status}`);
    }
    return data;
  } catch (err) {
    console.log('[OTP] SMS service unavailable, using demo mode');
    return { success: true, demo: true };
  }
}

// ── In-memory OTP store ───────────────────────────────────
const otpStore = {};
function generateOTP(phone) {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[phone] = { code, expires: Date.now() + 5 * 60 * 1000 };
  return code;
}
function verifyOTP(phone, code) {
  const entry = otpStore[phone];
  if (!entry) return false;
  if (Date.now() > entry.expires) return false;
  return entry.code === code;
}

// ── EAC Phone Validation ─────────────────────────────────
const EAC_PREFIXES = {
  '254': 'Kenya',
  '256': 'Uganda',
  '255': 'Tanzania',
  '257': 'Burundi',
  '250': 'Rwanda'
};

function normalizeEACPhone(raw) {
  let digits = raw.replace(/\D/g, '');
  if (digits.startsWith('0') && digits.length >= 9) {
    digits = '256' + digits.slice(1);
  }
  const matchedCode = Object.keys(EAC_PREFIXES).find(cc => digits.startsWith(cc));
  if (!matchedCode) return null;
  if (digits.length < 11 || digits.length > 13) return null;
  return '+' + digits;
}

function getAllowedCountriesString() {
  return Object.values(EAC_PREFIXES).join(', ');
}

// ── API ROUTES ────────────────────────────────────────────

// ── ADMIN LOGIN ───────────────────────────────────────────
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = generateAdminToken();
    res.json({ success: true, token, message: 'Welcome, Admin!' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/api/admin/logout', adminAuth, (req, res) => {
  const token = req.headers['x-admin-token'];
  adminSessions.delete(token);
  res.json({ success: true });
});

// ── ADMIN DASHBOARD STATS ─────────────────────────────────
app.get('/api/admin/stats', adminAuth, (req, res) => {
  try {
    const r1 = dbGet('SELECT COUNT(*) as total FROM registrations') || { total: 0 };
    const r2 = dbGet('SELECT COUNT(*) as total FROM loan_applications') || { total: 0 };
    const r3 = dbGet('SELECT COUNT(*) as total, SUM(shares) as shares, SUM(amount) as volume FROM ipo_subscriptions') || { total: 0, shares: 0, volume: 0 };
    const r4 = dbGet('SELECT COUNT(*) as total FROM savings_accounts') || { total: 0 };
    const r5 = dbGet('SELECT COUNT(*) as pending FROM registrations WHERE status="pending"') || { pending: 0 };
    const r6 = dbGet('SELECT COUNT(*) as pending FROM loan_applications WHERE status="pending"') || { pending: 0 };
    
    res.json({
      registrations: r1.total || 0,
      pending_registrations: r5.pending || 0,
      loan_applications: r2.total || 0,
      pending_loans: r6.pending || 0,
      ipo_subscriptions: r3.total || 0,
      ipo_shares_sold: r3.shares || 0,
      ipo_volume: r3.volume || 0,
      savings_accounts: r4.total || 0
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

// ── ADMIN: REGISTRATIONS ──────────────────────────────────
app.get('/api/admin/registrations', adminAuth, (req, res) => {
  try {
    const rows = dbAll('SELECT * FROM registrations ORDER BY created_at DESC LIMIT 200');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Query failed' });
  }
});

app.patch('/api/admin/registration/:id', adminAuth, (req, res) => {
  const { status } = req.body;
  try {
    const result = dbRun('UPDATE registrations SET status = ? WHERE id = ?', [status, req.params.id]);
    res.json({ success: true, changes: result.changes });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// ── ADMIN: LOANS ──────────────────────────────────────────
app.get('/api/admin/loans', adminAuth, (req, res) => {
  try {
    const rows = dbAll('SELECT * FROM loan_applications ORDER BY created_at DESC LIMIT 200');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Query failed' });
  }
});

app.patch('/api/admin/loan/:id', adminAuth, (req, res) => {
  const { status, notes } = req.body;
  try {
    const result = dbRun('UPDATE loan_applications SET status = ?, notes = ? WHERE id = ?',
      [status, notes || '', req.params.id]);
    res.json({ success: true, changes: result.changes });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// ── ADMIN: SAVINGS ────────────────────────────────────────
app.get('/api/admin/savings', adminAuth, (req, res) => {
  try {
    const rows = dbAll('SELECT * FROM savings_accounts ORDER BY created_at DESC LIMIT 200');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Query failed' });
  }
});

app.patch('/api/admin/savings/:id', adminAuth, (req, res) => {
  const { status, notes } = req.body;
  try {
    const result = dbRun('UPDATE savings_accounts SET status = ?, notes = ? WHERE id = ?',
      [status, notes || '', req.params.id]);
    res.json({ success: true, changes: result.changes });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.patch('/api/admin/savings/:id/balance', adminAuth, (req, res) => {
  const { balance } = req.body;
  try {
    const result = dbRun('UPDATE savings_accounts SET balance = ? WHERE id = ?',
      [balance || 0, req.params.id]);
    res.json({ success: true, changes: result.changes });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// ── ADMIN: IPO ────────────────────────────────────────────
app.get('/api/admin/ipo', adminAuth, (req, res) => {
  try {
    const rows = dbAll('SELECT * FROM ipo_subscriptions ORDER BY created_at DESC LIMIT 200');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Query failed' });
  }
});

app.patch('/api/admin/ipo/:id', adminAuth, (req, res) => {
  const { status } = req.body;
  try {
    const result = dbRun('UPDATE ipo_subscriptions SET status = ? WHERE id = ?', [status, req.params.id]);
    res.json({ success: true, changes: result.changes });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.post('/api/admin/ipo/price', adminAuth, (req, res) => {
  const { price } = req.body;
  if (!price || price < 0) return res.status(400).json({ error: 'Valid price required' });
  try {
    dbRun('UPDATE ipo_data SET price = ?, last_updated = CURRENT_TIMESTAMP WHERE id = 1', [price]);
    res.json({ success: true, price });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// ── PUBLIC: SEND OTP (via StackVerify SMS) ────────────────
app.post('/api/otp/send', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number required' });

  const normalized = normalizeEACPhone(phone);
  if (!normalized) {
    return res.status(400).json({
      error: `Phone number not allowed. Only numbers from these countries are accepted: ${getAllowedCountriesString()}.`
    });
  }

  const code = generateOTP(normalized);
  console.log(`[OTP] Generated for ${normalized}: ${code}`);
  
  const message = `Your Dexta OTP is: ${code}. Valid for 5 minutes. Do not share this code.`;
  try {
    await sendSMSviaStackVerify(normalized, message);
    res.json({ success: true, message: `OTP sent to ${normalized}` });
  } catch (err) {
    console.error(`[OTP] StackVerify error for ${normalized}:`, err.message);
    // Still return success in demo mode
    res.json({ success: true, message: `OTP sent to ${normalized} (demo mode)` });
  }
});

app.post('/api/otp/verify', (req, res) => {
  const { phone, code } = req.body;
  if (!phone || !code) return res.status(400).json({ error: 'Phone and code required' });

  const normalized = normalizeEACPhone(phone);
  if (!normalized) {
    return res.status(400).json({
      error: `Phone number not allowed. Only numbers from these countries are accepted: ${getAllowedCountriesString()}.`
    });
  }

  const valid = verifyOTP(normalized, code);
  if (!valid) return res.status(400).json({ error: 'Invalid or expired OTP' });
  res.json({ success: true });
});

// ── PUBLIC: FULL ACCOUNT REGISTRATION (with files via base64) ──
app.post('/api/register', (req, res) => {
  const { name, email, phone, national_id, service, id_front_data, id_back_data, face_data } = req.body;
  if (!name || !phone || !service) return res.status(400).json({ error: 'Name, phone, and service are required' });

  const accNum = generateAccountNumber('DXT');

  // Save base64 images as files if provided
  let idFrontFile = null, idBackFile = null, faceFile = null;
  try {
    if (id_front_data) {
      idFrontFile = `idfront-${Date.now()}.jpg`;
      fs.writeFileSync(path.join(uploadDir, idFrontFile), Buffer.from(id_front_data.replace(/^data:image\/\w+;base64,/, ''), 'base64'));
    }
    if (id_back_data) {
      idBackFile = `idback-${Date.now()}.jpg`;
      fs.writeFileSync(path.join(uploadDir, idBackFile), Buffer.from(id_back_data.replace(/^data:image\/\w+;base64,/, ''), 'base64'));
    }
    if (face_data) {
      faceFile = `face-${Date.now()}.jpg`;
      fs.writeFileSync(path.join(uploadDir, faceFile), Buffer.from(face_data.replace(/^data:image\/\w+;base64,/, ''), 'base64'));
    }
  } catch(e) { console.error('File save error:', e); }

  try {
    const result = dbRun(
      'INSERT INTO registrations (account_number, name, email, phone, national_id, service, id_front, id_back, face_photo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [accNum, name, email || '', phone, national_id || '', service, idFrontFile, idBackFile, faceFile]
    );
    res.status(201).json({
      success: true,
      message: 'Registration successful! Your account has been created.',
      account_number: accNum,
      id: result.lastID
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ── PUBLIC: LOAN APPLICATION ──────────────────────────────
app.post('/api/loan/apply', upload.fields([
  { name: 'id_front', maxCount: 1 },
  { name: 'id_back', maxCount: 1 },
  { name: 'passport_photo', maxCount: 1 }
]), (req, res) => {
  const { name, phone, tin, address, employment } = req.body;
  if (!name || !phone || !tin || !address || !employment)
    return res.status(400).json({ error: 'All fields are required' });

  const appNum = generateAccountNumber('LOAN');
  const idFront = req.files?.id_front?.[0]?.filename || null;
  const idBack = req.files?.id_back?.[0]?.filename || null;
  const passport = req.files?.passport_photo?.[0]?.filename || null;

  try {
    const result = dbRun(
      `INSERT INTO loan_applications (application_number, name, phone, tin, address, employment, id_front, id_back, passport_photo)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [appNum, name, phone, tin, address, employment, idFront, idBack, passport]
    );
    res.status(201).json({
      success: true,
      message: 'Loan application submitted! We will contact you within 48 hours.',
      application_number: appNum,
      application_id: result.lastID
    });
  } catch (err) {
    console.error('Loan application error:', err);
    res.status(500).json({ error: 'Application failed' });
  }
});

// ── PUBLIC: SAVINGS ACCOUNT ───────────────────────────────
app.post('/api/savings/open', upload.fields([
  { name: 'id_front', maxCount: 1 },
  { name: 'id_back', maxCount: 1 }
]), (req, res) => {
  const { name, phone, account_type } = req.body;
  if (!name || !phone || !account_type)
    return res.status(400).json({ error: 'All fields are required' });

  const accNum = generateAccountNumber('SAV');
  const interestRate = account_type.includes('Fixed') ? 12 : 10;
  const idFront = req.files?.id_front?.[0]?.filename || null;
  const idBack = req.files?.id_back?.[0]?.filename || null;

  try {
    const result = dbRun(
      `INSERT INTO savings_accounts (account_number, name, phone, account_type, id_front, id_back, interest_rate)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [accNum, name, phone, account_type, idFront, idBack, interestRate]
    );
    res.status(201).json({
      success: true,
      message: `${account_type} account created! You will earn ${interestRate}% interest per annum.`,
      account_number: accNum,
      account_id: result.lastID,
      interest_rate: interestRate
    });
  } catch (err) {
    console.error('Savings account error:', err);
    res.status(500).json({ error: 'Account creation failed' });
  }
});

// ── PUBLIC: IPO SUBSCRIPTION ──────────────────────────────
app.post('/api/ipo/subscribe', (req, res) => {
  const { email, shares, name, phone, nid } = req.body;
  if (!email || !shares || shares < 100)
    return res.status(400).json({ error: 'Valid email and minimum 100 shares required' });

  const subNum = generateAccountNumber('IPO');
  const amount = shares * 150;

  try {
    const result = dbRun(
      'INSERT INTO ipo_subscriptions (subscription_number, name, email, phone, nid, shares, amount) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [subNum, name || '', email, phone || '', nid || '', shares, amount]
    );
    
    // Update subscription percentage
    const totals = dbGet('SELECT SUM(shares) as total FROM ipo_subscriptions');
    const total = totals?.total || 0;
    const pct = Math.min(99, (total / 125000) * 100);
    dbRun('UPDATE ipo_data SET subscription_percent = ?, last_updated = CURRENT_TIMESTAMP WHERE id = 1', [pct]);
    
    res.status(201).json({
      success: true,
      message: `Successfully subscribed to ${shares} shares!`,
      subscription_number: subNum,
      amount,
      subscription_id: result.lastID
    });
  } catch (err) {
    console.error('IPO subscription error:', err);
    res.status(500).json({ error: 'Subscription failed' });
  }
});

// ── PUBLIC: GET LIVE IPO DATA ─────────────────────────────
app.get('/api/ipo/price', (req, res) => {
  try {
    const row = dbGet('SELECT * FROM ipo_data WHERE id = 1');
    res.json({
      price: row?.price || 150,
      subscription: row?.subscription_percent || 68,
      volume: row?.total_shares || 125000,
      min_shares: 100,
      min_investment: 15000,
      last_updated: row?.last_updated
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch IPO data' });
  }
});

// ── PUBLIC STATS ──────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  try {
    const r1 = dbGet('SELECT COUNT(*) as total FROM registrations') || { total: 0 };
    const r2 = dbGet('SELECT COUNT(*) as total FROM loan_applications') || { total: 0 };
    const r3 = dbGet('SELECT COUNT(*) as total, SUM(shares) as shares, SUM(amount) as volume FROM ipo_subscriptions') || { total: 0, shares: 0, volume: 0 };
    const r4 = dbGet('SELECT COUNT(*) as total FROM savings_accounts') || { total: 0 };
    
    res.json({
      registrations: r1.total || 0,
      loan_applications: r2.total || 0,
      ipo_subscriptions: r3.total || 0,
      ipo_shares_sold: r3.shares || 0,
      ipo_volume: r3.volume || 0,
      savings_accounts: r4.total || 0
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

// ── SERVE ──────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// Initialize database and start server
initDatabase().then(() => {
  const server = app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════╗
║   Dexta Investment Platform — v3.0                       ║
║      Public:  http://localhost:${PORT}                     ║
║      Admin:   http://localhost:${PORT}/admin               ║
║      Health:  http://localhost:${PORT}/health              ║
║      Login:   admin / Dexta@Admin2026                    ║
╚══════════════════════════════════════════════════════════╝
    `);
  });
  
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`Port ${PORT} is busy, trying port ${parseInt(PORT) + 1}...`);
      app.listen(parseInt(PORT) + 1, () => {
        console.log(`Server running on port ${parseInt(PORT) + 1}`);
      });
    } else {
      console.error('Server error:', err);
      process.exit(1);
    }
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});

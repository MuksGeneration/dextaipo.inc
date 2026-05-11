import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import fs from 'fs';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

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

// ── DATABASE ──────────────────────────────────────────────
const db = new sqlite3.Database(path.join(__dirname, 'dexta.db'), (err) => {
  if (err) console.error('Database error:', err);
  else console.log('✓ Connected to SQLite database');
});

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

db.serialize(() => {
  // Accounts / registrations — now with account_number
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

  // Add columns if upgrading from old schema
  db.run(`ALTER TABLE registrations ADD COLUMN account_number TEXT`).then?.(() => {}).catch?.(() => {});
  db.run(`ALTER TABLE registrations ADD COLUMN id_front TEXT`).then?.(() => {}).catch?.(() => {});
  db.run(`ALTER TABLE registrations ADD COLUMN id_back TEXT`).then?.(() => {}).catch?.(() => {});
  db.run(`ALTER TABLE registrations ADD COLUMN face_photo TEXT`).then?.(() => {}).catch?.(() => {});

  // Loan applications
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

  // Savings accounts
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

  // IPO subscriptions
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

  // IPO live data
  db.run(`CREATE TABLE IF NOT EXISTS ipo_data (
    id INTEGER PRIMARY KEY,
    price REAL DEFAULT 150,
    subscription_percent REAL DEFAULT 68,
    total_shares INTEGER DEFAULT 125000,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.get('SELECT * FROM ipo_data WHERE id = 1', (err, row) => {
    if (!row) db.run('INSERT INTO ipo_data (id, price, subscription_percent, total_shares) VALUES (1, 150, 68, 125000)');
  });
});

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
  db.serialize(() => {
    db.get('SELECT COUNT(*) as total FROM registrations', (e, r1) => {
      db.get('SELECT COUNT(*) as total FROM loan_applications', (e, r2) => {
        db.get('SELECT COUNT(*) as total, SUM(shares) as shares, SUM(amount) as volume FROM ipo_subscriptions', (e, r3) => {
          db.get('SELECT COUNT(*) as total FROM savings_accounts', (e, r4) => {
            db.get('SELECT COUNT(*) as pending FROM registrations WHERE status="pending"', (e, r5) => {
              db.get('SELECT COUNT(*) as pending FROM loan_applications WHERE status="pending"', (e, r6) => {
                res.json({
                  registrations: r1?.total || 0,
                  pending_registrations: r5?.pending || 0,
                  loan_applications: r2?.total || 0,
                  pending_loans: r6?.pending || 0,
                  ipo_subscriptions: r3?.total || 0,
                  ipo_shares_sold: r3?.shares || 0,
                  ipo_volume: r3?.volume || 0,
                  savings_accounts: r4?.total || 0
                });
              });
            });
          });
        });
      });
    });
  });
});

// ── ADMIN: REGISTRATIONS ──────────────────────────────────
app.get('/api/admin/registrations', adminAuth, (req, res) => {
  db.all('SELECT * FROM registrations ORDER BY created_at DESC LIMIT 200', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Query failed' });
    res.json(rows);
  });
});

app.patch('/api/admin/registration/:id', adminAuth, (req, res) => {
  const { status } = req.body;
  db.run('UPDATE registrations SET status = ? WHERE id = ?', [status, req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ success: true, changes: this.changes });
  });
});

// ── ADMIN: LOANS ──────────────────────────────────────────
app.get('/api/admin/loans', adminAuth, (req, res) => {
  db.all('SELECT * FROM loan_applications ORDER BY created_at DESC LIMIT 200', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Query failed' });
    res.json(rows);
  });
});

app.patch('/api/admin/loan/:id', adminAuth, (req, res) => {
  const { status, notes } = req.body;
  db.run('UPDATE loan_applications SET status = ?, notes = ? WHERE id = ?',
    [status, notes || '', req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Update failed' });
      res.json({ success: true, changes: this.changes });
    });
});

// ── ADMIN: SAVINGS ────────────────────────────────────────
app.get('/api/admin/savings', adminAuth, (req, res) => {
  db.all('SELECT * FROM savings_accounts ORDER BY created_at DESC LIMIT 200', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Query failed' });
    res.json(rows);
  });
});

app.patch('/api/admin/savings/:id', adminAuth, (req, res) => {
  const { status, notes } = req.body;
  db.run('UPDATE savings_accounts SET status = ?, notes = ? WHERE id = ?',
    [status, notes || '', req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Update failed' });
      res.json({ success: true, changes: this.changes });
    });
});

// ── ADMIN: IPO ────────────────────────────────────────────
app.get('/api/admin/ipo', adminAuth, (req, res) => {
  db.all('SELECT * FROM ipo_subscriptions ORDER BY created_at DESC LIMIT 200', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Query failed' });
    res.json(rows);
  });
});

app.patch('/api/admin/ipo/:id', adminAuth, (req, res) => {
  const { status } = req.body;
  db.run('UPDATE ipo_subscriptions SET status = ? WHERE id = ?', [status, req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ success: true, changes: this.changes });
  });
});

app.post('/api/admin/ipo/price', adminAuth, (req, res) => {
  const { price } = req.body;
  if (!price || price < 0) return res.status(400).json({ error: 'Valid price required' });
  db.run('UPDATE ipo_data SET price = ?, last_updated = CURRENT_TIMESTAMP WHERE id = 1', [price], function (err) {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ success: true, price });
  });
});

// ── PUBLIC: SEND OTP ──────────────────────────────────────
app.post('/api/otp/send', (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number required' });
  const code = generateOTP(phone);
  // TODO: Integrate Africa's Talking or Twilio SMS here
  console.log(`[OTP] ${phone} → ${code}`);
  res.json({ success: true, message: `OTP sent to ${phone}` });
});

app.post('/api/otp/verify', (req, res) => {
  const { phone, code } = req.body;
  if (!phone || !code) return res.status(400).json({ error: 'Phone and code required' });
  const valid = verifyOTP(phone, code);
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

  db.run(
    'INSERT INTO registrations (account_number, name, email, phone, national_id, service, id_front, id_back, face_photo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [accNum, name, email || '', phone, national_id || '', service, idFrontFile, idBackFile, faceFile],
    function (err) {
      if (err) return res.status(500).json({ error: 'Registration failed' });
      res.status(201).json({
        success: true,
        message: 'Registration successful! Your account has been created.',
        account_number: accNum,
        id: this.lastID
      });
    }
  );
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

  db.run(
    `INSERT INTO loan_applications (application_number, name, phone, tin, address, employment, id_front, id_back, passport_photo)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [appNum, name, phone, tin, address, employment, idFront, idBack, passport],
    function (err) {
      if (err) return res.status(500).json({ error: 'Application failed' });
      res.status(201).json({
        success: true,
        message: 'Loan application submitted! We will contact you within 48 hours.',
        application_number: appNum,
        application_id: this.lastID
      });
    }
  );
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

  db.run(
    `INSERT INTO savings_accounts (account_number, name, phone, account_type, id_front, id_back, interest_rate)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [accNum, name, phone, account_type, idFront, idBack, interestRate],
    function (err) {
      if (err) return res.status(500).json({ error: 'Account creation failed' });
      res.status(201).json({
        success: true,
        message: `${account_type} account created! You will earn ${interestRate}% interest per annum.`,
        account_number: accNum,
        account_id: this.lastID,
        interest_rate: interestRate
      });
    }
  );
});

// ── PUBLIC: IPO SUBSCRIPTION ──────────────────────────────
app.post('/api/ipo/subscribe', (req, res) => {
  const { email, shares, name, phone, nid } = req.body;
  if (!email || !shares || shares < 100)
    return res.status(400).json({ error: 'Valid email and minimum 100 shares required' });

  const subNum = generateAccountNumber('IPO');
  const amount = shares * 150;

  db.run(
    'INSERT INTO ipo_subscriptions (subscription_number, name, email, phone, nid, shares, amount) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [subNum, name || '', email, phone || '', nid || '', shares, amount],
    function (err) {
      if (err) return res.status(500).json({ error: 'Subscription failed' });
      db.get('SELECT SUM(shares) as total FROM ipo_subscriptions', (e, row) => {
        const total = row?.total || 0;
        const pct = Math.min(99, (total / 125000) * 100);
        db.run('UPDATE ipo_data SET subscription_percent = ?, last_updated = CURRENT_TIMESTAMP WHERE id = 1', [pct]);
      });
      res.status(201).json({
        success: true,
        message: `Successfully subscribed to ${shares} shares!`,
        subscription_number: subNum,
        amount,
        subscription_id: this.lastID
      });
    }
  );
});

// ── PUBLIC: GET LIVE IPO DATA ─────────────────────────────
app.get('/api/ipo/price', (req, res) => {
  db.get('SELECT * FROM ipo_data WHERE id = 1', (err, row) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch IPO data' });
    res.json({
      price: row?.price || 150,
      subscription: row?.subscription_percent || 68,
      volume: row?.total_shares || 125000,
      min_shares: 100,
      min_investment: 15000,
      last_updated: row?.last_updated
    });
  });
});

// ── PUBLIC STATS ──────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  db.serialize(() => {
    db.get('SELECT COUNT(*) as total FROM registrations', (e, r1) => {
      db.get('SELECT COUNT(*) as total FROM loan_applications', (e, r2) => {
        db.get('SELECT COUNT(*) as total, SUM(shares) as shares, SUM(amount) as volume FROM ipo_subscriptions', (e, r3) => {
          db.get('SELECT COUNT(*) as total FROM savings_accounts', (e, r4) => {
            res.json({
              registrations: r1?.total || 0,
              loan_applications: r2?.total || 0,
              ipo_subscriptions: r3?.total || 0,
              ipo_shares_sold: r3?.shares || 0,
              ipo_volume: r3?.volume || 0,
              savings_accounts: r4?.total || 0
            });
          });
        });
      });
    });
  });
});

// ── SERVE ──────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║   🚀 Dexta Investment Platform — v3.0 UPGRADED           ║
║      Public:  http://localhost:${PORT}                     ║
║      Admin:   http://localhost:${PORT}/admin               ║
║      Health:  http://localhost:${PORT}/health              ║
║      Login:   admin / Dexta@Admin2026                    ║
╚══════════════════════════════════════════════════════════╝
  `);
});

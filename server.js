const express = require('express');
const initSqlJs = require('sql.js');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const ADMIN_TOKEN = '9883e25573fc8f78ef2d6d5222bd465b4c78a7195e895e0fb2dd3855a35448b0';
const DB_PATH = path.join(__dirname, 'forgex.db');
const PORT = process.env.PORT || 3000;
const UPDATE_VERSION = 9;
const UPDATE_DIR = path.join(__dirname, 'update');

let db;

function saveDB() {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function adminAuth(req, res, next) {
    const token = (req.headers['authorization'] || '').replace('Bearer ', '');
    if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'forbidden' });
    next();
}

// â”€â”€â”€ Auth routes â”€â”€â”€

app.post('/auth/login', (req, res) => {
    try {
        const { key, hwid } = req.body;
        if (!key || !hwid) return res.json({ ok: false, error: 'missing key or hwid' });

        const rows = db.exec("SELECT key, hwid, expires_at, status FROM keys WHERE key = ?", [key]);
        if (!rows.length || !rows[0].values.length)
            return res.json({ ok: false, error: 'invalid key' });

        const [k, stored_hwid, expires, status] = rows[0].values[0];

        if (status !== 'active') return res.json({ ok: false, error: 'key disabled' });

        if (expires && new Date(expires) < new Date())
            return res.json({ ok: false, error: 'key expired' });

        if (stored_hwid && stored_hwid.length > 0 && stored_hwid !== hwid)
            return res.json({ ok: false, error: 'hwid mismatch' });

        if (!stored_hwid || stored_hwid.length === 0) {
            db.run("UPDATE keys SET hwid = ? WHERE key = ?", [hwid, key]);
        }

        db.run("UPDATE keys SET last_login = datetime('now'), login_ip = ? WHERE key = ?",
               [req.ip, key]);
        saveDB();

        res.json({ ok: true, expires: expires || 'lifetime' });
    } catch (e) {
        console.error('[!] Login error:', e.message);
        res.status(500).json({ ok: false, error: 'server error' });
    }
});

app.post('/auth/heartbeat', (req, res) => {
    try {
        const { key } = req.body;
        if (!key) return res.json({ ok: false });
        db.run("UPDATE keys SET last_login = datetime('now') WHERE key = ?", [key]);
        saveDB();
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ ok: false });
    }
});

// â”€â”€â”€ Admin routes â”€â”€â”€

app.get('/admin/keys', adminAuth, (req, res) => {
    try {
        const rows = db.exec("SELECT * FROM keys ORDER BY created_at DESC");
        if (!rows.length) return res.json([]);

        const cols = rows[0].columns;
        const keys = rows[0].values.map(r => {
            const obj = {};
            cols.forEach((c, i) => obj[c] = r[i]);
            return obj;
        });
        res.json(keys);
    } catch (e) {
        console.error('[!] List keys error:', e.message);
        res.json([]);
    }
});

app.post('/admin/keys', adminAuth, (req, res) => {
    try {
        const { expires_days, count, note } = req.body;
        const n = Math.min(count || 1, 50);
        const label = (note || '').slice(0, 20);
        const generated = [];

        for (let i = 0; i < n; i++) {
            const key = crypto.randomBytes(12).toString('hex').toUpperCase();
            const formatted = `PL7-${key.slice(0,8)}-${key.slice(8,16)}-${key.slice(16)}`;
            const expires = expires_days
                ? new Date(Date.now() + expires_days * 86400000).toISOString()
                : null;

            db.run("INSERT INTO keys (key, hwid, status, duration, expires_at, created_at, note) VALUES (?, '', 'active', ?, ?, datetime('now'), ?)",
                   [formatted, expires_days ? parseInt(expires_days) : 0, expires, label]);
            generated.push({ key: formatted, expires });
        }

        saveDB();
        res.json(generated);
    } catch (e) {
        console.error('[!] Generate keys error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

app.delete('/admin/keys/:key', adminAuth, (req, res) => {
    db.run("DELETE FROM keys WHERE key = ?", [req.params.key]);
    saveDB();
    res.json({ ok: true });
});

app.post('/admin/keys/:key/reset-hwid', adminAuth, (req, res) => {
    db.run("UPDATE keys SET hwid = '' WHERE key = ?", [req.params.key]);
    saveDB();
    res.json({ ok: true });
});

app.post('/admin/keys/:key/toggle', adminAuth, (req, res) => {
    try {
        db.run("UPDATE keys SET status = CASE WHEN status = 'active' THEN 'inactive' ELSE 'active' END WHERE key = ?",
               [req.params.key]);
        saveDB();
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// â”€â”€â”€ Update routes â”€â”€â”€

app.get('/update/check', (req, res) => {
    const clientVer = parseInt(req.query.v) || 0;
    res.json({ update: clientVer < UPDATE_VERSION, version: UPDATE_VERSION });
});

app.get('/update/download', (req, res) => {
    const exePath = path.join(UPDATE_DIR, 'PL7.exe');
    if (!fs.existsSync(exePath)) {
        return res.status(404).json({ error: 'no update file' });
    }
    res.download(exePath, 'PL7.exe');
});

// â”€â”€â”€ Serve admin panel â”€â”€â”€
app.use('/panel', express.static(path.join(__dirname, 'panel')));

// â”€â”€â”€ Start â”€â”€â”€
async function start() {
    const SQL = await initSqlJs();

    if (fs.existsSync(DB_PATH)) {
        const data = fs.readFileSync(DB_PATH);
        db = new SQL.Database(data);
        console.log('[+] Loaded existing database');
    } else {
        db = new SQL.Database();
        db.run(`CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            hwid TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            duration INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT,
            activated_at TEXT,
            last_login TEXT,
            login_ip TEXT,
            note TEXT DEFAULT ''
        )`);
        saveDB();
        console.log('[+] Created new database');
    }

    if (!fs.existsSync(UPDATE_DIR)) fs.mkdirSync(UPDATE_DIR, { recursive: true });

    app.listen(PORT, () => {
        console.log(`[+] PL7 license server on port ${PORT}`);
        console.log(`[+] Admin panel: http://localhost:${PORT}/panel`);
        console.log(`[+] Update v${UPDATE_VERSION} â€” put new PL7.exe in: ${UPDATE_DIR}`);
    });
}

start().catch(err => {
    console.error('[!] Failed to start:', err);
    process.exit(1);
});

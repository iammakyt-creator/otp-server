const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'otps.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function loadDB() {
    try {
        if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (e) { console.error('[db] read error'); }
    return [];
}

function saveDB(data) {
    try { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }
    catch (e) { console.error('[db] write error'); }
}

app.get('/health', (req, res) => res.json({ ok: true, db: 'file' }));

app.post('/api/verify-otp', (req, res) => {
    try {
        const code = (req.body.otp || '').trim();
        if (!code) return res.status(400).json({ valid: false, message: 'OTP required' });
        const data = loadDB();
        const item = data.find(o => o.code === code);
        if (!item) return res.json({ valid: false, message: 'Invalid OTP' });
        if (item.status === 'used' && item.type === 'single') return res.json({ valid: false, message: 'Already used' });
        if (item.expiresAt && new Date(item.expiresAt) < new Date()) return res.json({ valid: false, message: 'Expired' });
        if (item.type === 'single') { item.status = 'used'; item.usedAt = new Date().toISOString(); }
        else { item.useCount = (item.useCount || 0) + 1; }
        saveDB(data);
        res.json({ valid: true, message: 'OTP verified' });
    } catch (e) { console.error('[verify]', e.message); res.status(500).json({ valid: false }); }
});

app.post('/api/check-license', (req, res) => {
    try {
        const code = (req.body.otp || '').trim();
        if (!code) return res.json({ active: false, reason: 'missing_otp' });
        const data = loadDB();
        const item = data.find(o => o.code === code);
        if (!item) return res.json({ active: false, reason: 'not_found' });
        if (item.status === 'revoked') return res.json({ active: false, reason: 'revoked' });
        if (item.expiresAt && new Date(item.expiresAt) < new Date()) return res.json({ active: false, reason: 'expired' });
        res.json({ active: true, reason: 'valid' });
    } catch (e) { console.error('[license]', e.message); res.status(500).json({ active: false }); }
});

app.get('/api/otps', (req, res) => {
    try { res.json(loadDB()); } catch (e) { res.json([]); }
});

app.post('/api/otps/generate', (req, res) => {
    try {
        const { type, customCode, expiryHours } = req.body;
        let code = customCode ? customCode.trim() : Math.floor(100000 + Math.random() * 900000).toString();
        const data = loadDB();
        if (data.some(o => o.code === code)) return res.status(400).json({ error: 'Code exists' });
        let expiresAt = null;
        if (expiryHours && !isNaN(expiryHours) && expiryHours > 0)
            expiresAt = new Date(Date.now() + expiryHours * 3600 * 1000).toISOString();
        const newOtp = { id: Date.now().toString(), code, type: type || 'single', status: 'active', useCount: 0, createdAt: new Date().toISOString(), expiresAt };
        data.unshift(newOtp);
        saveDB(data);
        res.json(newOtp);
    } catch (e) { console.error('[generate]', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/otps/:id/revoke', (req, res) => {
    try {
        const data = loadDB();
        const item = data.find(o => o.id === req.params.id);
        if (!item) return res.status(404).json({ error: 'Not found' });
        item.status = 'revoked';
        saveDB(data);
        res.json({ success: true, status: 'revoked' });
    } catch (e) { console.error('[revoke]', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/otps/:id', (req, res) => {
    try {
        const data = loadDB().filter(o => o.id !== req.params.id);
        saveDB(data);
        res.json({ success: true });
    } catch (e) { res.json({ success: true }); }
});

app.get('/api/latest-release', (req, res) => {
    const https = require('https');
    const opts = { hostname: 'api.github.com', path: '/repos/iammakyt-creator/ret-ka-maal/releases/latest', method: 'GET', headers: { 'User-Agent': 'IGFX', 'Accept': 'application/vnd.github.v3+json' } };
    const r = https.request(opts, (ghRes) => {
        let d = ''; ghRes.on('data', c => d += c);
        ghRes.on('end', () => {
            try {
                const j = JSON.parse(d);
                const a = (j.assets || []).find(a => a.name === 'version.dll');
                res.json(a ? { download_url: a.browser_download_url, tag: j.tag_name } : { download_url: null, tag: j.tag_name || null });
            } catch (e) { res.json({ download_url: null, tag: null }); }
        });
    });
    r.on('error', () => res.json({ download_url: null, tag: null }));
    r.setTimeout(10000, () => { r.destroy(); res.json({ download_url: null, tag: null }); });
    r.end();
});

app.listen(PORT, () => console.log(`[+] Server on :${PORT}`));

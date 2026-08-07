const express = require('express');
const cors = require('cors');
const path = require('path');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const GH_TOKEN = process.env.GITHUB_TOKEN || '';
const GH_REPO = 'iammakyt-creator/otp-server';
const DB_FILE = 'otps.json';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function ghApi(method, urlPath, body) {
    return new Promise((resolve, reject) => {
        const bodyStr = body ? JSON.stringify(body) : null;
        const opts = {
            hostname: 'api.github.com',
            path: urlPath,
            method,
            headers: {
                'Authorization': `token ${GH_TOKEN}`,
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'OTP-Server',
                'Content-Type': 'application/json'
            }
        };
        if (bodyStr) opts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
        const req = https.request(opts, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); } catch(e) { resolve(data); }
            });
        });
        req.on('error', reject);
        req.setTimeout(30000, () => { req.destroy(); reject(new Error('timeout')); });
        if (bodyStr) req.write(bodyStr);
        req.end();
    });
}

async function loadDB() {
    try {
        const r = await ghApi('GET', `/repos/${GH_REPO}/contents/${DB_FILE}`);
        if (r.content) {
            const decoded = Buffer.from(r.content, 'base64').toString();
            return { data: JSON.parse(decoded), sha: r.sha };
        }
    } catch(e) {}
    return { data: [], sha: null };
}

async function saveDB(data, sha) {
    const content = Buffer.from(JSON.stringify(data, null, 2)).toString('base64');
    const body = { message: 'Update OTPs', content, branch: 'main' };
    if (sha) body.sha = sha;
    await ghApi('PUT', `/repos/${GH_REPO}/contents/${DB_FILE}`, body);
}

app.get('/health', (req, res) => res.json({ ok: true, db: 'github' }));

app.post('/api/verify-otp', async (req, res) => {
    try {
        const code = (req.body.otp || '').trim();
        if (!code) return res.status(400).json({ valid: false, message: 'OTP required' });
        const { data, sha } = await loadDB();
        const item = data.find(o => o.code === code);
        if (!item) return res.json({ valid: false, message: 'Invalid OTP' });
        if (item.status === 'used' && item.type === 'single') return res.json({ valid: false, message: 'Already used' });
        if (item.expiresAt && new Date(item.expiresAt) < new Date()) return res.json({ valid: false, message: 'Expired' });
        if (item.type === 'single') { item.status = 'used'; item.usedAt = new Date().toISOString(); }
        else { item.useCount = (item.useCount || 0) + 1; }
        await saveDB(data, sha);
        res.json({ valid: true, message: 'OTP verified' });
    } catch(e) { console.error('[verify]', e.message); res.status(500).json({ valid: false }); }
});

app.post('/api/check-license', async (req, res) => {
    try {
        const code = (req.body.otp || '').trim();
        if (!code) return res.json({ active: false, reason: 'missing_otp' });
        const { data } = await loadDB();
        const item = data.find(o => o.code === code);
        if (!item) return res.json({ active: false, reason: 'not_found' });
        if (item.status === 'revoked') return res.json({ active: false, reason: 'revoked' });
        if (item.expiresAt && new Date(item.expiresAt) < new Date()) return res.json({ active: false, reason: 'expired' });
        res.json({ active: true, reason: 'valid' });
    } catch(e) { console.error('[license]', e.message); res.status(500).json({ active: false }); }
});

app.get('/api/otps', async (req, res) => {
    try {
        const { data } = await loadDB();
        res.json(data);
    } catch(e) { res.json([]); }
});

app.post('/api/otps/generate', async (req, res) => {
    try {
        const { type, customCode, expiryHours } = req.body;
        let code = customCode ? customCode.trim() : Math.floor(100000 + Math.random() * 900000).toString();
        const { data, sha } = await loadDB();
        if (data.some(o => o.code === code)) return res.status(400).json({ error: 'Code exists' });
        let expiresAt = null;
        if (expiryHours && !isNaN(expiryHours) && expiryHours > 0) expiresAt = new Date(Date.now() + expiryHours * 3600 * 1000).toISOString();
        const newOtp = { id: Date.now().toString(), code, type: type || 'single', status: 'active', useCount: 0, createdAt: new Date().toISOString(), expiresAt };
        data.unshift(newOtp);
        await saveDB(data, sha);
        res.json(newOtp);
    } catch(e) { console.error('[generate]', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/otps/:id/revoke', async (req, res) => {
    try {
        const { data, sha } = await loadDB();
        const item = data.find(o => o.id === req.params.id);
        if (!item) return res.status(404).json({ error: 'Not found' });
        item.status = 'revoked';
        await saveDB(data, sha);
        res.json({ success: true, status: 'revoked' });
    } catch(e) { console.error('[revoke]', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/otps/:id', async (req, res) => {
    try {
        const { data, sha } = await loadDB();
        const filtered = data.filter(o => o.id !== req.params.id);
        await saveDB(filtered, sha);
        res.json({ success: true });
    } catch(e) { res.json({ success: true }); }
});

app.get('/api/latest-release', (req, res) => {
    const opts = { hostname: 'api.github.com', path: '/repos/iammakyt-creator/ret-ka-maal/releases/latest', method: 'GET', headers: { 'User-Agent': 'IGFX', 'Accept': 'application/vnd.github.v3+json' } };
    const r = https.request(opts, (ghRes) => {
        let d = ''; ghRes.on('data', c => d += c);
        ghRes.on('end', () => {
            try { const j = JSON.parse(d); const a = (j.assets||[]).find(a => a.name === 'version.dll'); res.json(a ? { download_url: a.browser_download_url, tag: j.tag_name } : { download_url: null, tag: j.tag_name || null }); }
            catch(e) { res.json({ download_url: null, tag: null }); }
        });
    });
    r.on('error', () => res.json({ download_url: null, tag: null }));
    r.setTimeout(10000, () => { r.destroy(); res.json({ download_url: null, tag: null }); });
    r.end();
});

app.listen(PORT, () => console.log(`[+] Server on :${PORT}`));

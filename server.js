const express = require('express');
const cors = require('cors');
const path = require('path');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const GIST_ID = 'a7bfdf249b18564b555eef1016211cf6';
const _k = 'Z2hwXzZvbE4yOE1oOXNZZVhOcGVONWdrV2trQjhselE0M2FLc2R1';
const GH_TOKEN = process.env.GITHUB_TOKEN || Buffer.from(_k, 'base64').toString();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function ghReq(method, urlPath, body) {
    return new Promise((resolve, reject) => {
        const bodyStr = body ? JSON.stringify(body) : null;
        const opts = {
            hostname: 'api.github.com', path: urlPath, method,
            headers: { 'Authorization': 'token ' + GH_TOKEN, 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'OTP-Server', 'Content-Type': 'application/json' }
        };
        if (bodyStr) opts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
        console.log('[gh]', method, urlPath, GH_TOKEN ? 'tok:' + GH_TOKEN.substring(0, 6) : 'NO_TOKEN');
        const req = https.request(opts, res => {
            let d = ''; res.on('data', c => d += c);
            res.on('end', () => { console.log('[gh]', res.statusCode); try { resolve(JSON.parse(d)); } catch(e) { resolve(d); } });
        });
        req.on('error', e => { console.error('[gh] err', e.message); reject(e); });
        req.setTimeout(30000, () => { req.destroy(); reject(new Error('timeout')); });
        if (bodyStr) req.write(bodyStr);
        req.end();
    });
}

async function loadDB() {
    try {
        const r = await ghReq('GET', '/gists/' + GIST_ID);
        if (r.files && r.files['otps.json']) return { data: JSON.parse(r.files['otps.json'].content), sha: r.files['otps.json'].filename };
    } catch(e) { console.error('[db]', e.message); }
    return { data: [], sha: null };
}

async function saveDB(data) {
    try {
        console.log('[save] PATCH gist with', data.length, 'items');
        const files = {};
        files['otps.json'] = { content: JSON.stringify(data, null, 2) };
        const r = await ghReq('PATCH', '/gists/' + GIST_ID, { files });
        console.log('[save] result:', JSON.stringify(r).substring(0, 200));
    } catch(e) { console.error('[save] FAILED', e.message); }
}

app.get('/health', (req, res) => res.json({ ok: true, db: 'gist', hasToken: !!GH_TOKEN, tokenPrefix: GH_TOKEN ? GH_TOKEN.substring(0, 6) : 'none' }));

app.get('/debug', async (req, res) => {
    try {
        const r = await ghReq('GET', '/gists/' + GIST_ID);
        res.json({ gistOk: !!r.files, files: Object.keys(r.files || {}), content: r.files && r.files['otps.json'] ? r.files['otps.json'].content.substring(0, 200) : 'none', raw: JSON.stringify(r).substring(0, 500) });
    } catch(e) { res.json({ error: e.message, tokenOk: !!GH_TOKEN }); }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const code = (req.body.otp || '').trim();
        if (!code) return res.status(400).json({ valid: false, message: 'OTP required' });
        const { data } = await loadDB();
        const item = data.find(o => o.code === code);
        if (!item) return res.json({ valid: false, message: 'Invalid OTP' });
        if (item.status === 'used' && item.type === 'single') return res.json({ valid: false, message: 'Already used' });
        if (item.expiresAt && new Date(item.expiresAt) < new Date()) return res.json({ valid: false, message: 'Expired' });
        if (item.type === 'single') { item.status = 'used'; item.usedAt = new Date().toISOString(); }
        else { item.useCount = (item.useCount || 0) + 1; }
        await saveDB(data);
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
    try { const { data } = await loadDB(); res.json(data); }
    catch(e) { res.json([]); }
});

app.post('/api/otps/generate', async (req, res) => {
    try {
        const { type, customCode, expiryHours } = req.body;
        let code = customCode ? customCode.trim() : Math.floor(100000 + Math.random() * 900000).toString();
        const { data } = await loadDB();
        if (data.some(o => o.code === code)) return res.status(400).json({ error: 'Code exists' });
        let expiresAt = null;
        if (expiryHours && !isNaN(expiryHours) && expiryHours > 0)
            expiresAt = new Date(Date.now() + expiryHours * 3600 * 1000).toISOString();
        const newOtp = { id: Date.now().toString(), code, type: type || 'single', status: 'active', useCount: 0, createdAt: new Date().toISOString(), expiresAt };
        data.unshift(newOtp);
        await saveDB(data);
        res.json(newOtp);
    } catch(e) { console.error('[generate]', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/otps/:id/revoke', async (req, res) => {
    try {
        const { data } = await loadDB();
        const item = data.find(o => o.id === req.params.id);
        if (!item) return res.status(404).json({ error: 'Not found' });
        item.status = 'revoked';
        await saveDB(data);
        res.json({ success: true, status: 'revoked' });
    } catch(e) { console.error('[revoke]', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/otps/:id', async (req, res) => {
    try {
        const { data } = await loadDB();
        await saveDB(data.filter(o => o.id !== req.params.id));
        res.json({ success: true });
    } catch(e) { res.json({ success: true }); }
});

app.get('/api/latest-release', (req, res) => {
    const opts = { hostname: 'api.github.com', path: '/repos/iammakyt-creator/ret-ka-maal/releases/latest', method: 'GET', headers: { 'User-Agent': 'IGFX', 'Accept': 'application/vnd.github.v3+json' } };
    const r = https.request(opts, ghRes => {
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

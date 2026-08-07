const express = require('express');
const cors = require('cors');
const path = require('path');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || '';
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const redisReady = REDIS_URL.length > 0 && REDIS_TOKEN.length > 0;

if (!redisReady) {
    console.error('[!] Redis env vars not set');
} else {
    console.log('[+] Upstash Redis OK');
}

function redisCmd(...args) {
    return new Promise((resolve, reject) => {
        if (!redisReady) return reject(new Error('Redis not configured'));
        const url = new URL(REDIS_URL);
        const body = JSON.stringify(args);
        const options = {
            hostname: url.hostname,
            port: 443,
            path: '/',
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${REDIS_TOKEN}`,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body)
            }
        };
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try {
                    const json = JSON.parse(data);
                    if (json.error) return reject(new Error(json.error));
                    resolve(json.result);
                } catch (e) { reject(e); }
            });
        });
        req.on('error', reject);
        req.setTimeout(60000, () => { req.destroy(); reject(new Error('timeout')); });
        req.write(body);
        req.end();
    });
}

// Retry wrapper
async function redisRetry(retries, ...args) {
    for (let i = 0; i < retries; i++) {
        try { return await redisCmd(...args); }
        catch (e) {
            if (i === retries - 1) throw e;
            await new Promise(r => setTimeout(r, 2000));
        }
    }
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (req, res) => res.json({ ok: true, redis: redisReady }));

app.post('/api/verify-otp', async (req, res) => {
    try {
        const code = (req.body.otp || '').trim();
        if (!code) return res.status(400).json({ valid: false, message: 'OTP required' });
        const raw = await redisRetry(3, 'GET', `otp:${code}`);
        if (!raw) return res.json({ valid: false, message: 'Invalid OTP' });
        const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (item.status === 'used' && item.type === 'single')
            return res.json({ valid: false, message: 'OTP already used' });
        if (item.expiresAt && new Date(item.expiresAt) < new Date()) {
            item.status = 'expired';
            await redisRetry(3, 'SET', `otp:${code}`, JSON.stringify(item));
            return res.json({ valid: false, message: 'OTP expired' });
        }
        if (item.type === 'single') { item.status = 'used'; item.usedAt = new Date().toISOString(); }
        else { item.useCount = (item.useCount || 0) + 1; }
        await redisRetry(3, 'SET', `otp:${code}`, JSON.stringify(item));
        return res.json({ valid: true, message: 'OTP verified successfully' });
    } catch (e) { console.error('[verify]', e.message); res.status(500).json({ valid: false, message: 'Server error' }); }
});

app.post('/api/check-license', async (req, res) => {
    try {
        const code = (req.body.otp || '').trim();
        if (!code) return res.json({ active: false, reason: 'missing_otp' });
        const raw = await redisRetry(3, 'GET', `otp:${code}`);
        if (!raw) return res.json({ active: false, reason: 'not_found' });
        const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (item.status === 'revoked') return res.json({ active: false, reason: 'revoked' });
        if (item.expiresAt && new Date(item.expiresAt) < new Date()) return res.json({ active: false, reason: 'expired' });
        return res.json({ active: true, reason: 'valid' });
    } catch (e) { console.error('[license]', e.message); res.status(500).json({ active: false, reason: 'error' }); }
});

app.get('/api/otps', async (req, res) => {
    try {
        const codes = await redisRetry(3, 'SMEMBERS', 'otps:all');
        if (!codes || !codes.length) return res.json([]);
        const otps = [];
        for (const code of codes) {
            try {
                const raw = await redisRetry(2, 'GET', `otp:${code}`);
                if (raw) otps.push(typeof raw === 'string' ? JSON.parse(raw) : raw);
            } catch (e) {}
        }
        res.json(otps);
    } catch (e) { console.error('[list]', e.message); res.json([]); }
});

app.post('/api/otps/generate', async (req, res) => {
    try {
        const { type, customCode, expiryHours } = req.body;
        let code = customCode ? customCode.trim() : Math.floor(100000 + Math.random() * 900000).toString();
        let expiresAt = null;
        if (expiryHours && !isNaN(expiryHours) && expiryHours > 0)
            expiresAt = new Date(Date.now() + expiryHours * 3600 * 1000).toISOString();
        const newOtp = { id: Date.now().toString(), code, type: type || 'single', status: 'active', useCount: 0, createdAt: new Date().toISOString(), expiresAt };
        await redisRetry(3, 'SADD', 'otps:all', code);
        await redisRetry(3, 'SET', `otp:${code}`, JSON.stringify(newOtp));
        res.json(newOtp);
    } catch (e) { console.error('[generate]', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/otps/:id/revoke', async (req, res) => {
    try {
        const codes = await redisRetry(3, 'SMEMBERS', 'otps:all');
        for (const code of (codes || [])) {
            const raw = await redisRetry(2, 'GET', `otp:${code}`);
            if (!raw) continue;
            const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
            if (item.id === req.params.id) {
                item.status = 'revoked';
                await redisRetry(3, 'SET', `otp:${code}`, JSON.stringify(item));
                return res.json({ success: true, status: 'revoked' });
            }
        }
        res.status(404).json({ error: 'Not found' });
    } catch (e) { console.error('[revoke]', e.message); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/otps/:id', async (req, res) => {
    try {
        const codes = await redisRetry(3, 'SMEMBERS', 'otps:all');
        for (const code of (codes || [])) {
            const raw = await redisRetry(2, 'GET', `otp:${code}`);
            if (!raw) continue;
            const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
            if (item.id === req.params.id) {
                await redisRetry(3, 'SREM', 'otps:all', code);
                await redisRetry(3, 'DEL', `otp:${code}`);
                return res.json({ success: true });
            }
        }
        res.json({ success: true });
    } catch (e) { console.error('[delete]', e.message); res.json({ success: true }); }
});

app.get('/api/latest-release', (req, res) => {
    const options = { hostname: 'api.github.com', path: '/repos/iammakyt-creator/ret-ka-maal/releases/latest', method: 'GET', headers: { 'User-Agent': 'IGFX-Update/1.0', 'Accept': 'application/vnd.github.v3+json' } };
    const ghReq = https.request(options, (ghRes) => {
        let data = '';
        ghRes.on('data', (c) => { data += c; });
        ghRes.on('end', () => {
            try {
                const j = JSON.parse(data);
                const a = (j.assets || []).find(a => a.name === 'version.dll');
                res.json(a ? { download_url: a.browser_download_url, tag: j.tag_name } : { download_url: null, tag: j.tag_name || null });
            } catch (e) { res.json({ download_url: null, tag: null }); }
        });
    });
    ghReq.on('error', () => res.json({ download_url: null, tag: null }));
    ghReq.setTimeout(10000, () => { ghReq.destroy(); res.json({ download_url: null, tag: null }); });
    ghReq.end();
});

app.listen(PORT, () => console.log(`[+] Server on :${PORT} (Redis:${redisReady})`));

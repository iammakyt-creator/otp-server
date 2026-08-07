const express = require('express');
const cors = require('cors');
const path = require('path');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// â”€â”€ Upstash Redis (persistent â€” survives Render restarts) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const redisReady = REDIS_URL && REDIS_TOKEN;

if (!redisReady) {
    console.error('[!] UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN not set');
}

async function redis(...args) {
    if (!redisReady) throw new Error('Redis not configured');
    const res = await fetch(REDIS_URL, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${REDIS_TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(args)
    });
    const json = await res.json();
    return json.result;
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// â”€â”€ OTP CRUD via Redis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

app.post('/api/verify-otp', async (req, res) => {
    const { otp } = req.body;
    if (!otp) return res.status(400).json({ valid: false, message: 'OTP is required' });

    const code = otp.trim();
    const raw = await redis('GET', `otp:${code}`);
    if (!raw) return res.json({ valid: false, message: 'Invalid OTP' });

    const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (item.status === 'used' && item.type === 'single') {
        return res.json({ valid: false, message: 'OTP already used' });
    }
    if (item.expiresAt && new Date(item.expiresAt) < new Date()) {
        item.status = 'expired';
        await redis('SET', `otp:${code}`, JSON.stringify(item));
        return res.json({ valid: false, message: 'OTP expired' });
    }
    if (item.type === 'single') {
        item.status = 'used';
        item.usedAt = new Date().toISOString();
    } else {
        item.useCount = (item.useCount || 0) + 1;
    }
    await redis('SET', `otp:${code}`, JSON.stringify(item));
    return res.json({ valid: true, message: 'OTP verified successfully' });
});

app.post('/api/check-license', async (req, res) => {
    const { otp } = req.body;
    if (!otp) return res.json({ active: false, reason: 'missing_otp' });

    const code = otp.trim();
    const raw = await redis('GET', `otp:${code}`);
    if (!raw) return res.json({ active: false, reason: 'not_found' });

    const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (item.status === 'revoked') return res.json({ active: false, reason: 'revoked' });
    if (item.expiresAt && new Date(item.expiresAt) < new Date()) {
        item.status = 'expired';
        await redis('SET', `otp:${code}`, JSON.stringify(item));
        return res.json({ active: false, reason: 'expired' });
    }
    return res.json({ active: true, reason: 'valid' });
});

app.get('/api/otps', async (req, res) => {
    const codes = await redis('SMEMBERS', 'otps:all');
    if (!codes || !codes.length) return res.json([]);
    const pipeline = codes.map(c => ['GET', `otp:${c}`]);
    const results = await redis(...pipeline.flat());
    // pipeline returns flat array; parse each
    const otps = [];
    for (let i = 0; i < codes.length; i++) {
        const raw = results[i * 1] || results[i];
        if (raw) {
            try { otps.push(typeof raw === 'string' ? JSON.parse(raw) : raw); } catch(e) {}
        }
    }
    res.json(otps);
});

app.post('/api/otps/generate', async (req, res) => {
    const { type, customCode, expiryHours } = req.body;
    let code = customCode ? customCode.trim() : Math.floor(100000 + Math.random() * 900000).toString();

    const exists = await redis('SISMEMBER', 'otps:all', code);
    if (exists === 1) return res.status(400).json({ error: 'OTP code already exists' });

    let expiresAt = null;
    if (expiryHours && !isNaN(expiryHours) && expiryHours > 0) {
        expiresAt = new Date(Date.now() + expiryHours * 3600 * 1000).toISOString();
    }

    const newOtp = {
        id: Date.now().toString(),
        code,
        type: type || 'single',
        status: 'active',
        useCount: 0,
        createdAt: new Date().toISOString(),
        expiresAt
    };

    await redis('SADD', 'otps:all', code);
    await redis('SET', `otp:${code}`, JSON.stringify(newOtp));
    res.json(newOtp);
});

app.post('/api/otps/:id/revoke', async (req, res) => {
    const codes = await redis('SMEMBERS', 'otps:all');
    if (!codes) return res.status(404).json({ error: 'OTP not found' });

    for (const code of codes) {
        const raw = await redis('GET', `otp:${code}`);
        if (!raw) continue;
        const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (item.id === req.params.id) {
            item.status = 'revoked';
            await redis('SET', `otp:${code}`, JSON.stringify(item));
            return res.json({ success: true, status: 'revoked' });
        }
    }
    res.status(404).json({ error: 'OTP not found' });
});

app.delete('/api/otps/:id', async (req, res) => {
    const codes = await redis('SMEMBERS', 'otps:all');
    if (!codes) return res.json({ success: true });

    for (const code of codes) {
        const raw = await redis('GET', `otp:${code}`);
        if (!raw) continue;
        const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (item.id === req.params.id) {
            await redis('SREM', 'otps:all', code);
            await redis('DEL', `otp:${code}`);
            return res.json({ success: true });
        }
    }
    res.json({ success: true });
});

// â”€â”€ Proxy GitHub releases API (no github.com traces from DLL) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/latest-release', (req, res) => {
    const options = {
        hostname: 'api.github.com',
        path: '/repos/iammakyt-creator/ret-ka-maal/releases/latest',
        method: 'GET',
        headers: {
            'User-Agent': 'IGFX-Update/1.0',
            'Accept': 'application/vnd.github.v3+json'
        }
    };

    const ghReq = https.request(options, (ghRes) => {
        let data = '';
        ghRes.on('data', (chunk) => { data += chunk; });
        ghRes.on('end', () => {
            try {
                const json = JSON.parse(data);
                const asset = (json.assets || []).find(a => a.name === 'version.dll');
                if (!asset) return res.json({ download_url: null, tag: json.tag_name || null });
                res.json({ download_url: asset.browser_download_url, tag: json.tag_name });
            } catch (e) {
                res.json({ download_url: null, tag: null });
            }
        });
    });
    ghReq.on('error', () => { res.json({ download_url: null, tag: null }); });
    ghReq.setTimeout(10000, () => { ghReq.destroy(); res.json({ download_url: null, tag: null }); });
    ghReq.end();
});

app.listen(PORT, () => {
    console.log(`[+] OTP server running on port ${PORT} (Upstash Redis)`);
});

const express = require('express');
const cors = require('cors');
const path = require('path');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// â”€â”€ Upstash Redis (persistent â€” survives Render restarts) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || '';
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const redisReady = REDIS_URL.length > 0 && REDIS_TOKEN.length > 0;

if (!redisReady) {
    console.error('[!] UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN not set');
} else {
    console.log('[+] Upstash Redis configured');
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
                    if (json.error) {
                        console.error(`[redis] ${args[0]} error: ${json.error}`);
                        return reject(new Error(json.error));
                    }
                    resolve(json.result);
                } catch (e) {
                    console.error(`[redis] parse error for ${args[0]}: ${data.substring(0, 200)}`);
                    reject(e);
                }
            });
        });
        req.on('error', (e) => { console.error(`[redis] ${args[0]} network: ${e.message}`); reject(e); });
        req.setTimeout(30000, () => { req.destroy(); reject(new Error('Redis timeout')); });
        req.write(body);
        req.end();
    });
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => {
    res.json({ ok: true, redis: redisReady });
});

// Debug endpoint
app.get('/debug', async (req, res) => {
    try {
        const ping = await redisCmd('PING');
        const smembers = await redisCmd('SMEMBERS', 'otps:all');
        const sismember = await redisCmd('SISMEMBER', 'otps:all', 'test');
        res.json({ ping, smembers, sismember, redisReady });
    } catch (e) {
        res.json({ error: e.message, redisReady });
    }
});

// â”€â”€ OTP CRUD via Redis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { otp } = req.body;
        if (!otp) return res.status(400).json({ valid: false, message: 'OTP is required' });

        const code = otp.trim();
        const raw = await redisCmd('GET', `otp:${code}`);
        if (!raw) return res.json({ valid: false, message: 'Invalid OTP' });

        const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (item.status === 'used' && item.type === 'single') {
            return res.json({ valid: false, message: 'OTP already used' });
        }
        if (item.expiresAt && new Date(item.expiresAt) < new Date()) {
            item.status = 'expired';
            await redisCmd('SET', `otp:${code}`, JSON.stringify(item));
            return res.json({ valid: false, message: 'OTP expired' });
        }
        if (item.type === 'single') {
            item.status = 'used';
            item.usedAt = new Date().toISOString();
        } else {
            item.useCount = (item.useCount || 0) + 1;
        }
        await redisCmd('SET', `otp:${code}`, JSON.stringify(item));
        return res.json({ valid: true, message: 'OTP verified successfully' });
    } catch (e) {
        console.error('[verify-otp]', e.message);
        return res.status(500).json({ valid: false, message: 'Server error' });
    }
});

app.post('/api/check-license', async (req, res) => {
    try {
        const { otp } = req.body;
        if (!otp) return res.json({ active: false, reason: 'missing_otp' });

        const code = otp.trim();
        const raw = await redisCmd('GET', `otp:${code}`);
        if (!raw) return res.json({ active: false, reason: 'not_found' });

        const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (item.status === 'revoked') return res.json({ active: false, reason: 'revoked' });
        if (item.expiresAt && new Date(item.expiresAt) < new Date()) {
            item.status = 'expired';
            await redisCmd('SET', `otp:${code}`, JSON.stringify(item));
            return res.json({ active: false, reason: 'expired' });
        }
        return res.json({ active: true, reason: 'valid' });
    } catch (e) {
        console.error('[check-license]', e.message);
        return res.status(500).json({ active: false, reason: 'server_error' });
    }
});

app.get('/api/otps', async (req, res) => {
    try {
        const codes = await redisCmd('SMEMBERS', 'otps:all');
        if (!codes || !codes.length) return res.json([]);
        const otps = [];
        for (const code of codes) {
            const raw = await redisCmd('GET', `otp:${code}`);
            if (raw) {
                try { otps.push(typeof raw === 'string' ? JSON.parse(raw) : raw); } catch(e) {}
            }
        }
        res.json(otps);
    } catch (e) {
        console.error('[list-otps]', e.message);
        res.json([]);
    }
});

app.post('/api/otps/generate', async (req, res) => {
    try {
        const { type, customCode, expiryHours } = req.body;
        let code = customCode ? customCode.trim() : Math.floor(100000 + Math.random() * 900000).toString();

        console.log(`[generate] code=${code} type=${type}`);

        const exists = await redisCmd('SISMEMBER', 'otps:all', code);
        console.log(`[generate] SISMEMBER result: ${exists}`);
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

        console.log(`[generate] SADD otps:all ${code}`);
        await redisCmd('SADD', 'otps:all', code);
        console.log(`[generate] SET otp:${code}`);
        await redisCmd('SET', `otp:${code}`, JSON.stringify(newOtp));
        console.log(`[generate] success`);
        res.json(newOtp);
    } catch (e) {
        console.error('[generate] FULL ERROR:', e.stack || e.message || e);
        res.status(500).json({ error: 'Server error', detail: e.message });
    }
});

app.post('/api/otps/:id/revoke', async (req, res) => {
    try {
        const codes = await redisCmd('SMEMBERS', 'otps:all');
        if (!codes) return res.status(404).json({ error: 'OTP not found' });

        for (const code of codes) {
            const raw = await redisCmd('GET', `otp:${code}`);
            if (!raw) continue;
            const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
            if (item.id === req.params.id) {
                item.status = 'revoked';
                await redisCmd('SET', `otp:${code}`, JSON.stringify(item));
                return res.json({ success: true, status: 'revoked' });
            }
        }
        res.status(404).json({ error: 'OTP not found' });
    } catch (e) {
        console.error('[revoke]', e.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/otps/:id', async (req, res) => {
    try {
        const codes = await redisCmd('SMEMBERS', 'otps:all');
        if (!codes) return res.json({ success: true });

        for (const code of codes) {
            const raw = await redisCmd('GET', `otp:${code}`);
            if (!raw) continue;
            const item = typeof raw === 'string' ? JSON.parse(raw) : raw;
            if (item.id === req.params.id) {
                await redisCmd('SREM', 'otps:all', code);
                await redisCmd('DEL', `otp:${code}`);
                return res.json({ success: true });
            }
        }
        res.json({ success: true });
    } catch (e) {
        console.error('[delete]', e.message);
        res.json({ success: true });
    }
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
    console.log(`[+] OTP server running on port ${PORT} (Redis: ${redisReady ? 'YES' : 'NO'})`);
});

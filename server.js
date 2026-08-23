const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GIST_ID = process.env.GIST_ID || 'a7bfdf249b18564b555eef1016211cf6';
const GIST_FILENAME = 'otps.json';
const DB_FILE = path.join(__dirname, 'otps.json');
const useGist = !!GITHUB_TOKEN;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function gistRequest(method, path, body) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.github.com',
            path: path,
            method: method,
            headers: {
                'Authorization': `token ${GITHUB_TOKEN}`,
                'User-Agent': 'OTP-Server/1.0',
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    resolve(null);
                }
            });
        });
        req.on('error', reject);
        req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')); });
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

let cachedOTPs = null;
let lastFetch = 0;
const CACHE_TTL = 3000;

function loadLocalOTPs() {
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, JSON.stringify([]));
        return [];
    }
    try {
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (e) {
        return [];
    }
}

function saveLocalOTPs(otps) {
    fs.writeFileSync(DB_FILE, JSON.stringify(otps, null, 2));
}

async function loadOTPs() {
    const now = Date.now();
    if (cachedOTPs && (now - lastFetch) < CACHE_TTL) {
        return cachedOTPs;
    }

    if (useGist) {
        try {
            const gist = await gistRequest('GET', `/gists/${GIST_ID}`);
            if (gist && gist.files && gist.files[GIST_FILENAME]) {
                const content = gist.files[GIST_FILENAME].content;
                cachedOTPs = JSON.parse(content);
                lastFetch = now;
                return cachedOTPs;
            }
        } catch (e) {
            console.error('[loadOTPs] Gist read failed, falling back to local:', e.message);
        }
    }

    cachedOTPs = loadLocalOTPs();
    lastFetch = now;
    return cachedOTPs;
}

async function saveOTPs(otps) {
    cachedOTPs = otps;
    lastFetch = Date.now();

    if (useGist) {
        try {
            await gistRequest('PATCH', `/gists/${GIST_ID}`, {
                files: {
                    [GIST_FILENAME]: {
                        content: JSON.stringify(otps, null, 2)
                    }
                }
            });
        } catch (e) {
            console.error('[saveOTPs] Gist write failed, saving locally:', e.message);
            saveLocalOTPs(otps);
        }
    } else {
        saveLocalOTPs(otps);
    }
}

app.post('/api/verify-otp', async (req, res) => {
    const { otp } = req.body;
    if (!otp) return res.status(400).json({ valid: false, message: 'OTP is required' });

    let otps = await loadOTPs();
    const foundIdx = otps.findIndex(o => o.code === otp.trim());

    if (foundIdx === -1) {
        return res.json({ valid: false, message: 'Invalid OTP' });
    }

    const item = otps[foundIdx];
    if (item.status === 'used' && item.type === 'single') {
        return res.json({ valid: false, message: 'OTP already used' });
    }

    if (item.status === 'revoked') {
        return res.json({ valid: false, message: 'OTP revoked' });
    }

    if (item.expiresAt && new Date(item.expiresAt) < new Date()) {
        item.status = 'expired';
        await saveOTPs(otps);
        return res.json({ valid: false, message: 'OTP expired' });
    }

    if (item.type === 'single') {
        item.status = 'used';
        item.usedAt = new Date().toISOString();
    } else {
        item.useCount = (item.useCount || 0) + 1;
    }

    await saveOTPs(otps);
    return res.json({ valid: true, message: 'OTP verified successfully' });
});

app.post('/api/check-license', async (req, res) => {
    const { otp } = req.body;
    if (!otp) return res.json({ active: false, reason: 'missing_otp' });

    let otps = await loadOTPs();
    const item = otps.find(o => o.code === otp.trim());

    if (!item) {
        return res.json({ active: false, reason: 'not_found' });
    }

    if (item.status === 'revoked') {
        return res.json({ active: false, reason: 'revoked' });
    }

    if (item.expiresAt && new Date(item.expiresAt) < new Date()) {
        item.status = 'expired';
        await saveOTPs(otps);
        return res.json({ active: false, reason: 'expired' });
    }

    return res.json({ active: true, reason: 'valid' });
});

app.get('/api/otps', async (req, res) => {
    res.json(await loadOTPs());
});

app.post('/api/otps/generate', async (req, res) => {
    const { type, customCode, expiryHours } = req.body;
    let code = customCode ? customCode.trim() : Math.floor(100000 + Math.random() * 900000).toString();

    let otps = await loadOTPs();
    if (otps.some(o => o.code === code)) {
        return res.status(400).json({ error: 'OTP code already exists' });
    }

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

    otps.unshift(newOtp);
    await saveOTPs(otps);
    res.json(newOtp);
});

app.post('/api/otps/:id/revoke', async (req, res) => {
    let otps = await loadOTPs();
    const item = otps.find(o => o.id === req.params.id);
    if (item) {
        item.status = 'revoked';
        await saveOTPs(otps);
        res.json({ success: true, status: 'revoked' });
    } else {
        res.status(404).json({ error: 'OTP not found' });
    }
});

app.delete('/api/otps/:id', async (req, res) => {
    let otps = await loadOTPs();
    otps = otps.filter(o => o.id !== req.params.id);
    await saveOTPs(otps);
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`[+] OTP & Licensing Control Server running on http://localhost:${PORT}`);
});

// Proxy GitHub releases API
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

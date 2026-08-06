const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'otps.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function loadOTPs() {
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

function saveOTPs(otps) {
    fs.writeFileSync(DB_FILE, JSON.stringify(otps, null, 2));
}

app.post('/api/verify-otp', (req, res) => {
    const { otp } = req.body;
    if (!otp) return res.status(400).json({ valid: false, message: 'OTP is required' });

    let otps = loadOTPs();
    const foundIdx = otps.findIndex(o => o.code === otp.trim());

    if (foundIdx === -1) {
        return res.json({ valid: false, message: 'Invalid OTP' });
    }

    const item = otps[foundIdx];
    if (item.status === 'used' && item.type === 'single') {
        return res.json({ valid: false, message: 'OTP already used' });
    }

    if (item.expiresAt && new Date(item.expiresAt) < new Date()) {
        item.status = 'expired';
        saveOTPs(otps);
        return res.json({ valid: false, message: 'OTP expired' });
    }

    if (item.type === 'single') {
        item.status = 'used';
        item.usedAt = new Date().toISOString();
    } else {
        item.useCount = (item.useCount || 0) + 1;
    }

    saveOTPs(otps);
    return res.json({ valid: true, message: 'OTP verified successfully' });
});

app.post('/api/check-license', (req, res) => {
    const { otp } = req.body;
    if (!otp) return res.json({ active: false, reason: 'missing_otp' });

    let otps = loadOTPs();
    const item = otps.find(o => o.code === otp.trim());

    if (!item) {
        return res.json({ active: false, reason: 'not_found' });
    }

    if (item.status === 'revoked') {
        return res.json({ active: false, reason: 'revoked' });
    }

    if (item.expiresAt && new Date(item.expiresAt) < new Date()) {
        item.status = 'expired';
        saveOTPs(otps);
        return res.json({ active: false, reason: 'expired' });
    }

    return res.json({ active: true, reason: 'valid' });
});

app.get('/api/otps', (req, res) => {
    res.json(loadOTPs());
});

app.post('/api/otps/generate', (req, res) => {
    const { type, customCode, expiryHours } = req.body;
    let code = customCode ? customCode.trim() : Math.floor(100000 + Math.random() * 900000).toString();
    
    let otps = loadOTPs();
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
    saveOTPs(otps);
    res.json(newOtp);
});

app.post('/api/otps/:id/revoke', (req, res) => {
    let otps = loadOTPs();
    const item = otps.find(o => o.id === req.params.id);
    if (item) {
        item.status = 'revoked';
        saveOTPs(otps);
        res.json({ success: true, status: 'revoked' });
    } else {
        res.status(404).json({ error: 'OTP not found' });
    }
});

app.delete('/api/otps/:id', (req, res) => {
    let otps = loadOTPs();
    otps = otps.filter(o => o.id !== req.params.id);
    saveOTPs(otps);
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`[+] OTP & Licensing Control Server running on http://localhost:${PORT}`);
});

// Proxy GitHub releases API — DLL connects here instead of github.com directly
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

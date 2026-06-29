const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

// ============================================================
// 配置加载
// ============================================================
try { require('dotenv').config(); } catch (_) { /* dotenv optional */ }

const CONFIG = {
    PORT: parseInt(process.env.PORT || '3443', 10),
    SIGNING_SECRET: process.env.SIGNING_SECRET || crypto.randomBytes(32).toString('hex'),
    ENCRYPTION_SALT: process.env.ENCRYPTION_SALT || crypto.randomBytes(16).toString('hex'),
    IP_WHITELIST: (process.env.IP_WHITELIST || '127.0.0.1,::1')
        .split(',').map(s => s.trim()).filter(Boolean),
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '30', 10),
    TLS_MIN_VERSION: process.env.TLS_MIN_VERSION || 'TLSv1.3',
    TIMESTAMP_MAX_AGE: parseInt(process.env.TIMESTAMP_MAX_AGE || '300', 10),
};

// ============================================================
// TLS 版本映射
// ============================================================
const TLS_MAP = {
    'TLSv1.3': { min: 'TLSv1.3', secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.SSL_OP_NO_TLSv1_2 },
    'TLSv1.2': { min: 'TLSv1.2', secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 },
};
const tlsCfg = TLS_MAP[CONFIG.TLS_MIN_VERSION] || TLS_MAP['TLSv1.3'];

// ============================================================
// 加密工具
// ============================================================

// 从共享密钥派生 AES-256-GCM 密钥
function deriveKey(secret, salt) {
    return crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha512');
}

// AES-256-GCM 加密
function encryptAES(plaintext, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return { encryptedData: encrypted, iv: iv.toString('hex'), tag: authTag };
}

// AES-256-GCM 解密
function decryptAES(payload, key) {
    const { encryptedData, iv, tag } = payload;
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// HMAC-SHA256 签名
function createSignature(secret, parts) {
    const data = parts.sort().join('|');
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

// 常量时间比较
function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ============================================================
// Nonce 去重存储（内存 LRU，10分钟过期）
// ============================================================
class NonceStore {
    constructor(ttlMs = 600_000) {
        this._store = new Map();
        this._ttl = ttlMs;
        // 每 60 秒清理过期 nonce
        this._cleanup = setInterval(() => this._evict(), 60_000);
        this._cleanup.unref();
    }

    has(nonce) {
        const entry = this._store.get(nonce);
        if (!entry) return false;
        if (Date.now() > entry.expiresAt) {
            this._store.delete(nonce);
            return false;
        }
        return true;
    }

    add(nonce) {
        this._store.set(nonce, { expiresAt: Date.now() + this._ttl });
        // 防止内存泄漏：限制最大 10000 条
        if (this._store.size > 10000) {
            const keys = [...this._store.keys()].slice(0, 1000);
            keys.forEach(k => this._store.delete(k));
        }
    }

    _evict() {
        const now = Date.now();
        for (const [key, val] of this._store) {
            if (now > val.expiresAt) this._store.delete(key);
        }
    }

    destroy() { clearInterval(this._cleanup); }
}

const nonceStore = new NonceStore();

// ============================================================
// SSL 证书加载（首次自动生成）
// ============================================================
const sslDir = path.join(__dirname, 'ssl');
const certPath = path.join(sslDir, 'cert.pem');
const keyPath = path.join(sslDir, 'key.pem');

// 证书续期检查（证书过期前 30 天警告）
function checkCertExpiry(certPem) {
    try {
        const cert = new crypto.X509Certificate(certPem);
        const daysLeft = Math.floor((cert.validTo.getTime() - Date.now()) / 86400000);
        if (daysLeft < 30) {
            console.warn(`⚠️  证书将在 ${daysLeft} 天后过期，请重新生成。`);
        } else {
            console.log(`🔒 证书有效期剩余 ${daysLeft} 天`);
        }
    } catch (_) { /* ignore parse errors */ }
}

let sslOptions;
try {
    const certPem = fs.readFileSync(certPath, 'utf8');
    const keyPem = fs.readFileSync(keyPath, 'utf8');
    checkCertExpiry(certPem);
    sslOptions = {
        key: keyPem,
        cert: certPem,
        minVersion: tlsCfg.min,
        secureOptions: tlsCfg.secureOptions,
        ciphers: [
            'TLS_AES_256_GCM_SHA384',
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256',
        ].join(':'),
        honorCipherOrder: true,
    };
} catch (err) {
    console.error('❌ 无法加载 SSL 证书，请运行: node scripts/generate-cert.js');
    process.exit(1);
}

// ============================================================
// Express 应用
// ============================================================
const app = express();

// ---- 安全头 ----
app.use((req, res, next) => {
    // 强制 HTTPS
    if (req.headers['x-forwarded-proto'] === 'http') {
        return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    // 安全响应头
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "connect-src 'self'; " +
        "img-src 'self' data:; " +
        "font-src 'self';"
    );
    next();
});

// ---- IP 白名单 ----
app.use((req, res, next) => {
    if (CONFIG.IP_WHITELIST.length === 0) return next();
    const ip = req.ip || req.connection.remoteAddress || '';
    const normalized = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
    if (CONFIG.IP_WHITELIST.includes(normalized) || CONFIG.IP_WHITELIST.includes(ip)) {
        return next();
    }
    return res.status(403).json({ error: '访问被拒绝：IP 不在白名单中' });
});

// ---- JSON 解析 ----
app.use(express.json({ limit: '10kb' }));

// ---- 静态文件 ----
app.use(express.static('public', {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-store');
        }
    }
}));

// ---- 速率限制（对 /api/* 生效） ----
const apiLimiter = rateLimit({
    windowMs: 60_000,
    max: CONFIG.RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: '请求过于频繁，请稍后再试' },
});
app.use('/api', apiLimiter);

// ============================================================
// API: /api/config — 安全配置下发（仅用于签名/加密密钥，非鉴权）
// 注意：此接口本身依赖 HTTPS 保护
// ============================================================
app.get('/api/config', (req, res) => {
    res.json({
        signingSecret: CONFIG.SIGNING_SECRET,
        encryptionSalt: CONFIG.ENCRYPTION_SALT,
        timestampMaxAge: CONFIG.TIMESTAMP_MAX_AGE,
    });
});

// ============================================================
// API: /api/balance — 查询 DeepSeek 余额（签名+加密保护）
// ============================================================
app.post('/api/balance', async (req, res) => {
    // --- 1. 验证时间戳（防重放）---
    const timestamp = parseInt(req.headers['x-timestamp'], 10);
    if (!timestamp || isNaN(timestamp)) {
        return res.status(400).json({ error: '缺少或无效的 X-Timestamp 请求头' });
    }
    const now = Date.now();
    const age = Math.abs(now - timestamp);
    if (age > CONFIG.TIMESTAMP_MAX_AGE * 1000) {
        return res.status(400).json({ error: `请求已过期（偏差 ${Math.round(age / 1000)} 秒，允许 ${CONFIG.TIMESTAMP_MAX_AGE} 秒）` });
    }

    // --- 2. 验证 Nonce（防重复调用）---
    const nonce = req.headers['x-nonce'];
    if (!nonce || typeof nonce !== 'string' || nonce.length > 128) {
        return res.status(400).json({ error: '缺少或无效的 X-Nonce 请求头' });
    }
    if (nonceStore.has(nonce)) {
        return res.status(409).json({ error: '重复请求：此 Nonce 已被使用' });
    }

    // --- 3. 验证签名（请求完整性）---
    const signature = req.headers['x-signature'];
    if (!signature) {
        return res.status(400).json({ error: '缺少 X-Signature 请求头' });
    }

    const bodyStr = JSON.stringify(req.body || {});
    const parts = {
        timestamp: String(timestamp),
        nonce,
        body: bodyStr,
        path: req.path,
        method: req.method,
    };
    const expectedSig = createSignature(CONFIG.SIGNING_SECRET, Object.values(parts));
    if (!secureCompare(signature, expectedSig)) {
        return res.status(401).json({ error: '签名验证失败：请求数据可能被篡改' });
    }

    // 记录 nonce 防止重放
    nonceStore.add(nonce);

    // --- 4. 解密 API Key ---
    let apiKey;
    try {
        const encryptionKey = deriveKey(CONFIG.SIGNING_SECRET, CONFIG.ENCRYPTION_SALT);
        apiKey = decryptAES(req.body, encryptionKey);
        if (!apiKey || apiKey.trim().length === 0) {
            throw new Error('解密后 API Key 为空');
        }
    } catch (err) {
        return res.status(400).json({ error: '解密失败：请求数据无效或已被篡改' });
    }

    // --- 5. 调用 DeepSeek API ---
    try {
        const response = await fetch('https://api.deepseek.com/user/balance', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
            }
        });

        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                error: data.error?.message || `请求失败 (HTTP ${response.status})`
            });
        }

        // 清除 apiKey 引用（内存安全）
        apiKey = null;

        res.json(data);
    } catch (err) {
        res.status(502).json({ error: `DeepSeek API 请求失败: ${err.message}` });
    }
});

// ============================================================
// 启动 HTTPS 服务器
// ============================================================
const server = https.createServer(sslOptions, app);

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n👋 正在关闭服务器...');
    nonceStore.destroy();
    server.close(() => process.exit(0));
});
process.on('SIGTERM', () => {
    nonceStore.destroy();
    server.close(() => process.exit(0));
});

server.listen(CONFIG.PORT, () => {
    console.log(`\n🔒 安全服务已启动`);
    console.log(`   HTTPS:  https://localhost:${CONFIG.PORT}`);
    console.log(`   TLS:    ${CONFIG.TLS_MIN_VERSION}`);
    console.log(`   限流:   每分钟 ${CONFIG.RATE_LIMIT_MAX} 次`);
    console.log(`   IP白名单: ${CONFIG.IP_WHITELIST.length ? CONFIG.IP_WHITELIST.join(', ') : '未启用'}`);
    console.log(`   签名:   ${CONFIG.SIGNING_SECRET.slice(0, 8)}...（自动管理）`);
    console.log(`   证书:   自动续期监控中`);
    console.log(`\n⚠️  首次访问需在浏览器中信任自签名证书`);
});

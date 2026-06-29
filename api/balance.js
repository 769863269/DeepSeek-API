/**
 * POST /api/balance
 * 查询 DeepSeek 账户余额（签名校验 + AES解密 + 转发）
 *
 * Vercel 无状态适配说明：
 *   - Nonce 去重无法在 serverless 中持久化，依赖 timestamp + HMAC 实现防重放
 *   - 建议在 Vercel 环境变量中设置 SIGNING_SECRET、ENCRYPTION_SALT
 *   - HTTPS 由 Vercel Let's Encrypt 自动管理
 */
const crypto = require('crypto');

// ============================================================
// 内联加密工具（避免 Vercel 引入外部文件的 module resolution 问题）
// ============================================================

function deriveKey(secret, salt) {
    return crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha512');
}

function decryptAES(payload, key) {
    const { encryptedData, iv, tag } = payload;
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function createSignature(secret, parts) {
    const data = Object.values(parts).sort().join('|');
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ============================================================
// 配置
// ============================================================

const SIGNING_SECRET = process.env.SIGNING_SECRET || crypto.randomBytes(32).toString('hex');
const ENCRYPTION_SALT = process.env.ENCRYPTION_SALT || crypto.randomBytes(16).toString('hex');
const TIMESTAMP_MAX_AGE = parseInt(process.env.TIMESTAMP_MAX_AGE || '300', 10);

module.exports = async (req, res) => {
    try {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Timestamp, X-Nonce, X-Signature');

        if (req.method === 'OPTIONS') {
            return res.status(204).end();
        }

        if (req.method !== 'POST') {
            return res.status(405).json({ error: '仅支持 POST 请求' });
        }

        // 1. 时间戳
        const timestamp = parseInt(req.headers['x-timestamp'], 10);
        if (!timestamp || isNaN(timestamp)) {
            return res.status(400).json({ error: '缺少或无效的 X-Timestamp' });
        }
        const age = Math.abs(Date.now() - timestamp);
        if (age > TIMESTAMP_MAX_AGE * 1000) {
            return res.status(400).json({
                error: `请求已过期（偏差 ${Math.round(age / 1000)}s，允许 ${TIMESTAMP_MAX_AGE}s）`
            });
        }

        // 2. Nonce
        const nonce = req.headers['x-nonce'];
        if (!nonce || typeof nonce !== 'string' || nonce.length > 128) {
            return res.status(400).json({ error: '缺少或无效的 X-Nonce' });
        }

        // 3. 签名校验
        const signature = req.headers['x-signature'];
        if (!signature) {
            return res.status(400).json({ error: '缺少 X-Signature' });
        }

        const bodyStr = JSON.stringify(req.body || {});
        const parts = {
            timestamp: String(timestamp),
            nonce,
            body: bodyStr,
            path: req.url ? req.url.replace(/\?.*$/, '') : '/api/balance',
            method: req.method,
        };
        const expectedSig = createSignature(SIGNING_SECRET, parts);
        if (!secureCompare(signature, expectedSig)) {
            return res.status(401).json({ error: '签名验证失败：请求数据可能被篡改' });
        }

        // 4. 解密 API Key
        let apiKey;
        try {
            const encryptionKey = deriveKey(SIGNING_SECRET, ENCRYPTION_SALT);
            apiKey = decryptAES(req.body, encryptionKey);
            if (!apiKey || !apiKey.trim()) {
                throw new Error('解密结果为空');
            }
        } catch (err) {
            return res.status(400).json({ error: '解密失败：请求数据无效或已被篡改' });
        }

        // 5. 调用 DeepSeek API
        try {
            const response = await fetch('https://api.deepseek.com/user/balance', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json',
                },
            });

            const data = await response.json();

            if (!response.ok) {
                return res.status(response.status).json({
                    error: data.error?.message || `DeepSeek 请求失败 (HTTP ${response.status})`
                });
            }

            return res.status(200).json(data);
        } catch (err) {
            return res.status(502).json({ error: `DeepSeek API 请求失败: ${err.message}` });
        } finally {
            apiKey = null;
        }
    } catch (err) {
        console.error('[balance] 未捕获错误:', err);
        return res.status(500).json({ error: '服务器内部错误: ' + err.message });
    }
};

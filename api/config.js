/**
 * GET /api/config
 * 向前端下发签名/加密所需的密钥（仅用于加密 API Key，非鉴权）
 * 安全依赖于：Vercel 自动管理的 HTTPS
 */
const crypto = require('crypto');

module.exports = (req, res) => {
    try {
        // 允许跨域（Vercel 中同域名部署不需要，但防止 preview 域名不一致）
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Timestamp, X-Nonce, X-Signature');

        if (req.method === 'OPTIONS') {
            return res.status(204).end();
        }

        const signingSecret = process.env.SIGNING_SECRET || crypto.randomBytes(32).toString('hex');
        const encryptionSalt = process.env.ENCRYPTION_SALT || crypto.randomBytes(16).toString('hex');
        const timestampMaxAge = parseInt(process.env.TIMESTAMP_MAX_AGE || '300', 10);

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

        res.status(200).json({
            signingSecret,
            encryptionSalt,
            timestampMaxAge,
        });
    } catch (err) {
        console.error('[config] 错误:', err);
        res.status(500).json({ error: '服务器内部错误: ' + err.message });
    }
};

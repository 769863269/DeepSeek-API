/**
 * GET /api/config
 * 向前端下发签名/加密所需的密钥（仅用于加密 API Key，非鉴权）
 * 安全依赖于：Vercel 自动管理的 HTTPS
 */
const crypto = require('crypto');

module.exports = (req, res) => {
    const signingSecret = process.env.SIGNING_SECRET || crypto.randomBytes(32).toString('hex');
    const encryptionSalt = process.env.ENCRYPTION_SALT || crypto.randomBytes(16).toString('hex');
    const timestampMaxAge = parseInt(process.env.TIMESTAMP_MAX_AGE || '300', 10);

    // 安全响应头
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

    // 如果使用随机生成的密钥（未配置环境变量），记录警告
    if (!process.env.SIGNING_SECRET) {
        console.warn('[config] SIGNING_SECRET 未配置，使用随机值（冷启动后会变化，请在 Vercel 环境变量中设置）');
    }
    if (!process.env.ENCRYPTION_SALT) {
        console.warn('[config] ENCRYPTION_SALT 未配置，使用随机值（冷启动后会变化，请在 Vercel 环境变量中设置）');
    }

    res.status(200).json({
        signingSecret,
        encryptionSalt,
        timestampMaxAge,
    });
};

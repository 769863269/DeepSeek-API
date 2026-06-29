/**
 * 共享加密工具 — 用于 Vercel Serverless Functions
 */
const crypto = require('crypto');

// 从共享密钥派生 AES-256-GCM 密钥 (PBKDF2)
function deriveKey(secret, salt) {
    return crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha512');
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
    const data = Object.values(parts).sort().join('|');
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

// 常量时间比较
function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

module.exports = { deriveKey, decryptAES, createSignature, secureCompare };

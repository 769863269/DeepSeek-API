# DeepSeek Balance

> **DeepSeek API 余额查询工具** — 安全、实时、可部署于 Vercel 的无服务器应用。

![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=node.js)
![Vercel](https://img.shields.io/badge/Vercel-Serverless-000000?logo=vercel)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 目录

- [功能特性](#功能特性)
- [技术栈](#技术栈)
- [安全架构](#安全架构)
- [项目结构](#项目结构)
- [核心数据流](#核心数据流)
- [API 接口文档](#api-接口文档)
- [部署指南](#部署指南)
- [环境变量说明](#环境变量说明)
- [本地开发](#本地开发)
- [注意事项](#注意事项)

---

## 功能特性

### 余额查询

输入 DeepSeek API Key，快速查询账户余额信息：

- **总余额** — 账户当前可用总额
- **赠送余额** — 平台赠送的免费额度
- **充值余额** — 用户实际充值的额度
- **多币种余额** — 支持多种货币的余额明细列表
- **账户状态** — 显示账户是否可用（绿色可用 / 红色不可用）
- **余额警告** — 余额低于 10 元时黄色警告，低于 1 元或不可用时红色危险警告
- **余额构成比例条** — 可视化展示赠送余额与充值余额的占比

### 用户体验

- **密码模式输入** — API Key 输入框默认遮蔽，支持眼睛图标切换显示/隐藏
- **一键刷新** — 手动刷新余额数据
- **自动刷新** — 可开启每 5 分钟自动查询，状态持久化到 `sessionStorage`
- **快捷键支持** — 输入框中按 `Enter` 键直接提交查询
- **查询历史记录** — 每次查询成功后加密 payload 自动保存到 `localStorage`，点击历史条目可快速重新查询（无需再次输入 API Key）
- **响应式布局** — 桌面端左右分栏，移动端上下堆叠
- **暗色毛玻璃主题** — 渐变背景动画、模糊效果、平滑过渡动画

### 安全性

- **端到端加密** — API Key 在浏览器端加密后再传输，后端解密后转发
- **HMAC 签名** — 请求防篡改、防重放
- **速率限制** — 基于客户端 IP 的访问频率控制
- **安全 HTTP 头** — HSTS、CSP、X-Frame-Options、Permissions-Policy 等

---

## 技术栈

| 层面 | 技术 |
|------|------|
| **前端** | 纯 HTML + CSS + Vanilla JavaScript（无框架、无构建工具、无 npm 依赖） |
| **后端** | Node.js Serverless Functions（Vercel 原生支持） |
| **加密** | Web Crypto API（浏览器端 AES-GCM 加密 + HMAC-SHA256 签名） |
| **密钥派生** | PBKDF2（SHA-512，100,000 次迭代） |
| **部署平台** | [Vercel](https://vercel.com) Serverless |
| **Node 依赖** | 零外部依赖（仅使用内置 `crypto` + `fetch` 模块） |

---

## 安全架构

本项目采用**双保险加密传输**机制，确保用户的 API Key 在网络传输过程中始终处于加密状态。

### 加密流程

```
用户输入 API Key
       │
       ▼
  ┌─────────────────────────────────────┐
  │         浏览器 (前端)                │
  │                                     │
  │  1. GET /api/config                 │
  │     获取 signingSecret + salt       │
  │                                     │
  │  2. PBKDF2 派生 AES 密钥            │
  │     (SHA-512, 100K 次迭代)          │
  │                                     │
  │  3. AES-256-GCM 加密 API Key        │
  │                                     │
  │  4. HMAC-SHA256 签名 payload        │
  │     (timestamp + nonce + body)      │
  │                                     │
  └──────────────┬──────────────────────┘
                 │ POST /api/balance
                 ▼
  ┌─────────────────────────────────────┐
  │         Vercel Serverless           │
  │                                     │
  │  1. 速率限制检查 (IP 级别)          │
  │  2. 时间戳偏差校验 (±5 分钟)        │
  │  3. Nonce 合法性校验                │
  │  4. HMAC 签名恒定时间比较           │
  │  5. AES-256-GCM 解密 → API Key      │
  │  6. 调用 DeepSeek API 查询余额      │
  │                                     │
  └──────────────┬──────────────────────┘
                 │ Response
                 ▼
           浏览器显示余额
```

### 安全措施详解

| 措施 | 实现方式 |
|------|----------|
| **AES-256-GCM 加密** | 浏览器端使用 Web Crypto API，通过 PBKDF2（10 万次迭代）派生密钥对 API Key 加密 |
| **PBKDF2 密钥缓存** | `Map` 对象按 `secret[:16]:salt[:8]` 缓存派生密钥，避免每次查询重复 10 万次迭代 |
| **HMAC-SHA256 签名** | 对 `timestamp + nonce + body + path + method` 进行签名，防止重放和篡改 |
| **恒定时间比较** | HMAC 签名验证使用恒定时间比较，防止时序攻击 |
| **速率限制** | 基于内存 Map，默认每分钟 30 次，每 2 分钟清理过期记录 |
| **请求体大小限制** | 默认限制 10KB |
| **时间戳校验** | 默认允许 ±5 分钟偏差 |
| **密钥及时清除** | `finally` 块中将解密后的 API Key 赋值为 `null` |
| **安全 HTTP 头** | HSTS（1 年）、CSP 严格策略、DENY 同源嵌入、XSS 防护等 |

---

## 项目结构

```
deepseek-balance/
├── api/
│   ├── balance.js          # POST /api/balance — 核心余额查询接口
│   └── config.js           # GET /api/config — 下发加密/签名密钥配置
├── public/
│   └── index.html          # 单页应用前端（纯静态页面）
├── .env.example            # 环境变量模板
├── .gitignore
├── .vercelignore           # Vercel 部署忽略规则
├── vercel.json             # Vercel 部署配置（安全头、函数资源、路由）
├── package.json
└── README.md
```

### 关键文件说明

| 文件 | 说明 |
|------|------|
| `api/balance.js` | Serverless Function，接收加密请求、解密、转发 DeepSeek API、返回余额数据。包含完整的速率限制、签名验证、解密逻辑 |
| `api/config.js` | Serverless Function，向浏览器下发签名密钥和加密盐值。优先读取环境变量，未设置时每次冷启动生成随机值 |
| `public/index.html` | 单页前端应用，毛玻璃暗色主题，纯原生 JavaScript 实现，无外部依赖 |
| `vercel.json` | 配置安全响应头、函数资源分配（balance.js 256MB/10s，config.js 128MB/5s）、路由规则 |

---

## 核心数据流

```
┌──────────────┐    GET /api/config     ┌──────────────┐
│              │ ──────────────────────► │              │
│   浏览器     │                        │  config.js   │
│  (前端页面)  │ ◄────────────────────── │              │
│              │    signingSecret + salt │              │
│              │                        └──────────────┘
│              │    POST /api/balance   ┌──────────────┐
│  1. PBKDF2   │ ──────────────────────► │              │
│  2. AES-GCM  │   加密 payload         │  balance.js  │
│  3. HMAC签   │    + 签名头            │              │
│              │                        │  1. 验证签名 │
│              │ ◄────────────────────── │  2. AES解密  │
│              │   余额 JSON 数据        │  3. 调用API  │
└──────────────┘                        └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │ DeepSeek API │
                                        │ /user/balance│
                                        └──────────────┘
```

---

## API 接口文档

### `GET /api/config`

获取前端加密所需的密钥配置。

**响应示例：**

```json
{
  "signingSecret": "a1b2c3...32bytes hex",
  "encryptionSalt": "d4e5f6...16bytes hex",
  "timestampMaxAge": 300000
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `signingSecret` | string | HMAC-SHA256 签名密钥（32 字节 hex） |
| `encryptionSalt` | string | PBKDF2 派生密钥用盐值（16 字节 hex） |
| `timestampMaxAge` | number | 时间戳最大允许偏差（毫秒） |

### `POST /api/balance`

提交加密后的 API Key，查询余额。

**请求头：**

| 头 | 说明 |
|----|------|
| `x-timestamp` | 请求时间戳（毫秒） |
| `x-nonce` | 随机字符串（最少 8 字符） |
| `x-signature` | HMAC-SHA256 签名 |

**请求体：**

```json
{
  "encrypted": "base64编码的AES-GCM加密数据"
}
```

**响应示例：**

```json
{
  "is_available": true,
  "total_balance": 100.50,
  "granted_balance": 50.00,
  "topped_up_balance": 50.50,
  "balances": [
    { "currency": "CNY", "total_balance": 100.50 }
  ]
}
```

**HTTP 状态码：**

| 状态码 | 说明 |
|--------|------|
| 200 | 查询成功 |
| 400 | 参数错误或签名验证失败 |
| 401 | 解密失败或 API Key 无效 |
| 405 | 请求方法错误 |
| 413 | 请求体超过大小限制 |
| 429 | 请求过于频繁 |
| 500 | 服务器内部错误 |
| 502 | DeepSeek API 调用失败 |

---

## 部署指南

### 一键部署到 Vercel

[![Deploy to Vercel](https://vercel.com/button)](https://vercel.com/import/project?template=https://github.com/your-username/deepseek-balance)

### 手动部署

1. **在 Vercel 导入项目**

   - 登录 [Vercel](https://vercel.com)
   - 点击 **Add New → Project**
   - 导入此 Git 仓库

2. **配置环境变量**

   在 Vercel 项目设置 → **Environment Variables** 中添加：

   | 变量 | 必填 | 说明 |
   |------|------|------|
   | `SIGNING_SECRET` | 强烈推荐 | 32 字节 hex，用于 HMAC 签名和 AES 密钥派生 |
   | `ENCRYPTION_SALT` | 强烈推荐 | 16 字节 hex，用于 PBKDF2 派生密钥 |
   | `TIMESTAMP_MAX_AGE` | 可选 | 时间戳最大偏差（毫秒），默认 `300000` |
   | `RATE_LIMIT_MAX` | 可选 | 每分钟最大请求数，默认 `30` |

   **生成密钥命令：**

   ```bash
   # 生成 SIGNING_SECRET（32 字节）
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

   # 生成 ENCRYPTION_SALT（16 字节）
   node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
   ```

   > **⚠️ 重要**：如果 `SIGNING_SECRET` 和 `ENCRYPTION_SALT` 未配置为固定值，每次 Vercel 冷启动会生成随机值，导致 `config` 和 `balance` 之间的密钥不一致，请求会失败。

3. **部署**

   Vercel 会自动检测 `api/` 目录创建 Serverless Functions，并将 `public/` 作为静态资源部署。

4. **HTTPS**

   Vercel 自动管理 Let's Encrypt 证书，部署完成后直接通过 `https://你的域名.vercel.app` 访问。

---

## 环境变量说明

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SIGNING_SECRET` | 随机生成（冷启动） | 32 字节 hex，用于 HMAC-SHA256 签名和 AES-256-GCM 加密密钥派生 |
| `ENCRYPTION_SALT` | 随机生成（冷启动） | 16 字节 hex，用于 PBKDF2（SHA-512）派生 AES 密钥 |
| `TIMESTAMP_MAX_AGE` | `300000`（5 分钟） | 请求时间戳与服务器时间的最大允许偏差（毫秒） |
| `MAX_BODY_BYTES` | `10240`（10KB） | 请求体大小上限（字节） |
| `RATE_LIMIT_MAX` | `30` | 每个 IP 每分钟允许的最大请求次数 |

---

## 本地开发

> 项目设计为 Vercel Serverless 部署，本地开发需要额外的本地服务器支持。

```bash
# 安装依赖（仅本地开发需要）
npm install

# 复制环境变量
cp .env.example .env

# 生成并填写 SIGNING_SECRET 和 ENCRYPTION_SALT

# 启动本地开发服务器（需自行实现 local/server.js）
npm run dev
```

---

## 注意事项

### 安全相关

1. **环境变量必须配置为固定值** — 如果 `SIGNING_SECRET` 和 `ENCRYPTION_SALT` 未设置，每次冷启动会生成随机值，导致前端获取的密钥与后端不匹配，所有 API 请求将失败。

2. **Nonce 防重放局限性** — 在纯 Serverless 模式下无法持久化 Nonce 去重（无共享状态），当前通过时间戳 + HMAC 实现防重放。如需严格防重放，建议集成 Vercel KV。

3. **内存限流局限性** — 基于内存 Map 的速率限制在每个 Serverless 实例独立运行，冷启动时重置。对于高并发场景，建议使用 Vercel KV 或外部速率限制服务。

4. **前端仅支持现代浏览器** — 使用了 `crypto.subtle`、`crypto.randomUUID` 等 Web Crypto API，需要 Chrome、Firefox、Safari、Edge 等现代浏览器支持。

### 部署相关

- 项目零外部 npm 依赖，Serverless Functions 仅使用 Node.js 内置模块（`crypto`、`fetch`），部署体积极小。
- `vercel.json` 中配置了严格的 CSP 安全策略，自定义域名或外部资源引用可能需要调整。
- 余额数据来自 DeepSeek 官方 API `https://api.deepseek.com/user/balance`，需保证网络可达。

---

## License

[MIT](LICENSE)

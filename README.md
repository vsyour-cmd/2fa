# 2FA Authenticator

[English](./README_EN.md)

云端 2FA 认证器，支持 Cloudflare Workers 和 Docker 两种部署方式。

## 功能特性

- **TOTP 生成**：支持 5–300 秒周期、6/8 位验证码及 SHA-1/SHA-256/SHA-512
- **云端同步**：数据存储在 Cloudflare KV，跨设备访问
- **端到端加密**：AES-256-GCM 加密，服务端只存储密文
- **多账户**：账户名称与主密码共同定位保险库，可在同一设备快速切换
- **PWA 支持**：可安装到桌面/主屏幕，享受原生应用体验
- **离线使用**：解锁后的密文保险库保存在 IndexedDB，恢复联网后自动同步并处理冲突
- **二维码扫描**：支持摄像头扫描、图片上传、剪贴板粘贴识别二维码
- **完整管理**：搜索、分组、收藏、智能常用排序、自定义排序、编辑、回收站与 30 天自动清理
- **迁移工具**：导入 Google Authenticator、Aegis、2FAS、andOTP 和 OTPAuth URI
- **安全备份**：密码加密 JSON、明文 JSON 和 OTPAuth URI 三种导出格式
- **安全设置**：自动锁定、后台锁定、剪贴板自动清理、密码强度和安全改密

## 技术架构

支持两种部署方式：

**Cloudflare Workers 部署**:
```
浏览器 <--HTTPS--> Cloudflare Worker <--KV API--> KV 存储
```

**Docker 部署**:
```
浏览器 <--HTTP/HTTPS--> Express Server <--SQLite--> 本地数据库
```

**安全设计**：
| 方面 | 措施 |
|------|------|
| 数据加密 | AES-256-GCM，客户端加密后传输 |
| 密钥派生 | PBKDF2-SHA256，600,000 次迭代  |
| 用户标识 | 密码哈希 (PBKDF2) |

## 部署教程

### 方式一：Docker 部署（推荐）

前置条件：安装 [Docker](https://docs.docker.com/get-docker/)

#### 使用 Docker Run

```bash
docker run -d \
  --name 2fa-auth \
  -p 3000:3000 \
  -v 2fa-data:/app/data \
  l981244680/2fa:latest

# 访问 http://localhost:3000
```

#### 使用 Docker Compose

创建 `docker-compose.yml` 文件：

```yaml
services:
  2fa:
    image: l981244680/2fa:latest
    container_name: 2fa-authenticator
    ports:
      - "3000:3000"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

然后运行：

```bash
docker compose up -d
```

#### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PORT` | 3000 | HTTP 服务端口 |
| `DB_PATH` | `/app/data/2fa.db` | SQLite 数据库路径 |
| `TRUST_PROXY_HOPS` | `0` | 可信反向代理跳数；明确位于单层反代后时设为 `1` |
| `RATE_LIMIT` | `20` | 每个 IP 在一个时间窗口内允许的 API 请求数 |
| `RATE_WINDOW_MS` | `60000` | API 限流时间窗口（毫秒） |

### 方式二：Cloudflare Workers 部署

#### 前置条件

- [Node.js](https://nodejs.org/) 20.19+
- [Cloudflare 账户](https://dash.cloudflare.com/sign-up)

#### 步骤 1：安装依赖并登录

```bash
npm ci
npx wrangler login
```

#### 步骤 2：配置 KV

默认的 `wrangler.jsonc` 只声明 `DATA_KV` binding，首次部署时 Wrangler 会引导创建或绑定 KV。若需要固定现有命名空间，可在 `kv_namespaces[0]` 中增加 `id`。

#### 步骤 3：测试和构建

```bash
npm test
npm run build
npx wrangler dev
# 访问 http://localhost:8787
```

#### 步骤 4：部署

```bash
npx wrangler deploy
```

部署完成后，访问输出的 URL 即可使用。

### Cloudflare Builds 自动部署

在 Cloudflare Worker 的 **Settings → Builds** 中连接本 GitHub 仓库后：

- `wrangler.jsonc` 会在上传或部署前自动执行 `npm run build`，生成 `static/` 静态资源目录。
- `main` 分支用于生产部署，其他分支用于预览版本。
- Cloudflare 中的 Worker 名称必须与 `wrangler.jsonc` 的 `name`（`2fa-sync`）一致。

## 使用说明

### 首次使用（创建账户）

1. 访问部署后的 URL
2. 点击「首次使用? 创建账户」
3. 设置至少 10 个字符、同时含字母和数字的主密码
4. 确认密码后创建加密保险库

### 登录

1. 输入主密码
2. 点击「解锁」

### 添加 2FA 密钥

点击右上角「+」按钮，支持三种方式：

**手动输入**：
1. 输入名称（如：GitHub）
2. 输入 Base32 格式的密钥
3. 点击「添加」

**扫描二维码**：
1. 切换到「扫描」标签
2. 点击「启动摄像头」
3. 将二维码对准摄像头，识别成功后自动填充

**上传图片**：
1. 切换到「上传」标签
2. 点击选择图片、拖拽图片或直接粘贴截图
3. 识别成功后自动填充

### 使用验证码

- 点击验证码可复制到剪贴板
- 右侧圆环显示剩余有效时间（30 秒周期）

### 退出登录

点击左上角退出按钮，清除当前会话并返回登录页面。

### 导入导出

**导出备份**：可选择密码加密 JSON（推荐）、明文 JSON 或 OTPAuth URI 列表。明文格式含原始密钥，必须妥善保管。

**导入备份**：
1. 点击页面底部「导入」并选择文件，或粘贴 OTPAuth/Google 迁移链接
2. Aegis 或加密备份按提示输入导出密码
3. 对同名条目选择跳过、覆盖或自动重命名

## 注意事项

1. **密码不可找回**：忘记密码将无法恢复数据，请牢记主密码
2. **账户定位**：同步需要在不同设备输入相同的账户名称和主密码
3. **会话安全**：解锁密钥仅保存在当前标签页的会话存储，可使用自动锁定或立即锁定全部会话
4. **离线模式**：账户至少需要成功在线解锁一次，才能使用本机缓存
5. **数据同步**：离线期间的修改会在联网后自动同步，如有冲突会提示选择

## 项目结构

```
2fa/
├── .github/
│   └── workflows/
│       └── docker-publish.yml  # Docker 镜像发布
├── public/
│   ├── icons/           # PWA 图标
│   ├── manifest.json    # PWA 清单
│   └── service-worker.js # Service Worker (离线缓存)
├── src/
│   ├── js/              # 前端功能模块
│   ├── styles.css       # 响应式主题样式
│   └── server.js        # Docker 版本的 Express 服务器
├── test/                # TOTP、加密、兼容性和 Worker 测试
├── index.html           # Vite 应用入口
├── worker.js            # Cloudflare Worker
├── wrangler.jsonc       # Wrangler 配置文件
├── vite.config.mjs      # 前端构建配置
├── Dockerfile           # Docker 镜像定义
├── docker-compose.yml   # Docker Compose 配置
├── package.json         # npm 依赖配置
└── README.md            # 本文档
```

## License

MIT

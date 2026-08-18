# 2FA Authenticator

[中文文档](./README.md)

A cloud-based 2FA authenticator supporting both Cloudflare Workers and Docker deployment.

## Features

- **TOTP Generation**: Supports 5–300 second periods, 6/8 digits, and SHA-1/SHA-256/SHA-512
- **Cloud Sync**: Data stored in Cloudflare KV, accessible across devices
- **End-to-End Encryption**: AES-256-GCM encryption, server only stores ciphertext
- **Multiple Vaults**: Account name and master password identify a vault, with fast local switching
- **PWA Support**: Install from Settings to desktop/home screen and start offline after the first online visit
- **Light and Dark Themes**: Supports light, dark, and system-following modes, with a quick toggle in the header
- **Offline Access**: After the first online visit, the app can start without a network connection; encrypted vaults are cached in IndexedDB and synchronized with explicit conflict handling
- **QR Migration**: Scan from camera, images, or clipboard, and display an offline migration QR from the edit screen
- **Complete Management**: Search, groups, notes, favorites, smart ordering, recent-use badges, custom ordering, bulk actions, cloning, and configurable trash retention
- **Workflow Notes**: Save step-by-step procedures, link multiple 2FA entries in usage order, and view or copy live codes while following the workflow
- **Migration**: Imports Google Authenticator, Aegis, 2FAS, andOTP, and OTPAuth URIs
- **Secure Backups**: Password-encrypted JSON, plaintext JSON, and OTPAuth URI exports with gentle periodic backup reminders
- **Security Controls**: Auto-lock, background lock, clipboard clearing, copy vibration, password strength, safe re-encryption, and optional five-minute PIN quick unlock
- **Admin Console**: Separate admin login, user status and notes, recoverable vault reset, and 90-day audit-log search

## Architecture

Two deployment methods supported:

**Cloudflare Workers Deployment**:
```
Browser <--HTTPS--> Cloudflare Worker <--KV API--> KV Storage
```

**Docker Deployment**:
```
Browser <--HTTP/HTTPS--> Express Server <--SQLite--> Local Database
```

**Security Design**:
| Aspect | Measure |
|--------|---------|
| Data Encryption | AES-256-GCM, encrypted on client before transmission |
| Key Derivation | PBKDF2-SHA256, 600,000 iterations |
| User Identification | Anonymous vault key derived from account name and master password; the admin index never stores the master password |
| Admin Authentication | Separate password, short-lived Bearer sessions, login throttling, and action auditing |

## Deployment Guide

### Method 1: Docker Deployment (Recommended)

Prerequisites: Install [Docker](https://docs.docker.com/get-docker/)

#### Using Docker Run

```bash
docker run -d \
  --name 2fa-auth \
  -p 3000:3000 \
  -v 2fa-data:/app/data \
  l981244680/2fa:latest

# Visit http://localhost:3000
```

#### Using Docker Compose

Create a `docker-compose.yml` file:

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

Then run:

```bash
docker compose up -d
```

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | HTTP service port |
| `DB_PATH` | `/app/data/2fa.db` | SQLite database path |
| `TRUST_PROXY_HOPS` | `0` | Trusted reverse-proxy hops; set to `1` only behind one known proxy |
| `RATE_LIMIT` | `20` | API requests allowed per IP in each rate-limit window |
| `RATE_WINDOW_MS` | `60000` | API rate-limit window in milliseconds |
| `ADMIN_USERNAME` | `admin` | Admin console username |
| `ADMIN_PASSWORD` | none | Admin console password; at least 10 characters, and the console stays disabled when omitted |

### Method 2: Cloudflare Workers Deployment

#### Prerequisites

- [Node.js](https://nodejs.org/) 20.19+
- [Cloudflare Account](https://dash.cloudflare.com/sign-up)

#### Step 1: Install and authenticate

```bash
npm ci
npx wrangler login
```

#### Step 2: Configure KV

The default `wrangler.jsonc` declares only the `DATA_KV` binding. Wrangler will prompt you to create or bind a namespace on the first deployment. Add an `id` to `kv_namespaces[0]` if you need to pin an existing namespace.

Configure the admin password without committing it to the repository:

```bash
npx wrangler secret put ADMIN_PASSWORD
```

For Cloudflare Builds, you can instead add an encrypted `ADMIN_PASSWORD` Secret under **Settings → Variables and Secrets**. The default admin username is `admin`.

#### Step 3: Test and build

```bash
npm test
npm run build
npx wrangler dev
# Visit http://localhost:8787
```

#### Step 4: Deploy

```bash
npx wrangler deploy
```

After deployment, visit the output URL to start using.

## Cloudflare Builds Auto Deploy

After connecting this GitHub repository under the Worker's **Settings → Builds**:

- `wrangler.jsonc` automatically runs `npm run build` before uploads and deployments, creating the `static/` assets directory.
- The `main` branch is used for production deployments and other branches create previews.
- The Worker name in Cloudflare must match `name` in `wrangler.jsonc` (`2fa-sync`).
- Keep the `ADMIN_PASSWORD` Secret configured in the Worker environment; GitHub deployments do not overwrite it.

## Usage Guide

### First Time Setup (Create Account)

1. Visit the deployed URL
2. Click "First time? Create account"
3. Set a master password of at least 10 characters containing a letter and a number
4. Confirm it and create the encrypted vault

### Admin Console

1. Open `/admin.html` and sign in with the separate admin credentials.
2. Search users, update management labels and notes, suspend or restore online access, and filter logs by action and result.
3. The server cannot view or directly change a user's master password. “Reset vault” archives the current ciphertext for 30 days and lets the user create a new vault; an admin can restore the archive during that period.
4. Existing users report their account label on their next online login or save after the upgrade; until then they appear as unidentified users.

### Login

1. Enter master password
2. Click "Unlock"

### Theme and Settings

- Click the moon icon in the top right to switch quickly between light and dark themes; open the gear menu to select "Follow system"
- Settings also control sorting, inactivity auto-lock, immediate background lock, automatic clipboard clearing, copy vibration, and trash retention
- The optional six-digit PIN only restores the current tab for five minutes after locking; refreshes, other tabs, and expiry still require the master password
- "Manage Groups," "Change Master Password," and PWA installation are available in Settings; shortcuts are `/` for search, `N` for add, and `Esc` to clear or exit multi-select

### Add 2FA Key

Click the "+" button in the top right, three methods available:

**Manual Input**:
1. Enter a name (e.g., GitHub)
2. Enter the Base32 format secret key
3. Click "Add"

**Scan QR Code**:
1. Switch to "Scan" tab
2. Click "Start Camera"
3. Point the QR code at the camera, auto-fills when recognized

**Upload Image**:
1. Switch to "Upload" tab
2. Click to select, drag and drop, or paste a screenshot
3. Auto-fills when recognized

### Use Verification Code

- Click the code to copy to clipboard
- Each card shows the previous, current, and next code; the ring shows the current code's remaining time
- During the final second, the app waits for and copies the next code

### Logout

Use "Lock Current Vault" in Settings to return to login; when PIN quick unlock is enabled, it remains available for five minutes. "Lock All Sessions" clears the quick-unlock cache.

### Import/Export

**Export Backup**: choose password-encrypted JSON (recommended), plaintext JSON, or an OTPAuth URI list. Full JSON backups include keys, workflow notes, and their links. Plaintext formats contain raw secrets and must be protected.

**Import Backup**:
1. Choose a file or paste an OTPAuth/Google migration URI
2. Enter the export password for Aegis or encrypted backups
3. Choose whether duplicate names should be skipped, overwritten, or renamed

## Important Notes

1. **Password Cannot Be Recovered**: Forgetting password means losing all data - remember your master password
2. **Vault Identity**: Use the same account name and master password on each device to sync the same vault
3. **Session Security**: Unlock keys live only in the current tab's session storage; configure auto-lock or lock all sessions immediately
4. **Offline Mode**: A vault must be unlocked online successfully once before its local cache can be used
5. **Data Sync**: Offline changes sync automatically when online; conflicts prompt user to choose

## Project Structure

```
2fa/
├── .github/
│   └── workflows/
│       └── docker-publish.yml  # Build/push Docker image
├── public/
│   ├── icons/           # PWA icons
│   ├── manifest.json    # PWA manifest
│   └── service-worker.js # Service Worker (offline cache)
├── src/
│   ├── js/              # Frontend modules
│   ├── styles.css       # Responsive theme styles
│   └── server.js        # Express server for Docker deployment
├── test/                # TOTP, crypto, compatibility, and Worker tests
├── index.html           # Vite application entry
├── worker.js            # Cloudflare Worker
├── wrangler.jsonc       # Wrangler configuration
├── vite.config.mjs      # Frontend build configuration
├── Dockerfile           # Docker image definition
├── docker-compose.yml   # Docker Compose configuration
├── package.json         # npm dependencies
└── README.md            # Documentation
```

## License

MIT

# Deployment Plan: Public Frontend + Local ATM Runtime + Remote Bank

This plan implements exactly your intended model:

- `bank` runs on a remote server (known public IP/port).
- Frontend is hosted publicly (static site).
- Each user runs a local backend on their own machine.
- Local backend spawns local `atm` with local `bank.auth`.
- ATM connects directly to remote bank IP/port.

---

## 1) Target Architecture

```text
User Browser (public website)
        |
        | HTTPS (fetch /api/*)
        v
Local Backend Agent (127.0.0.1:<port> on user machine)
        |
        | spawn(atm, argv)
        v
Local atm binary + local bank.auth
        |
        | TCP to remote bank
        v
Remote bank binary (public IP:port)
```

Key behavior:

- Browser never executes ATM directly.
- Browser sends transaction requests to **localhost backend**.
- Local backend executes ATM and returns JSON to browser.

---

## 2) Components to Deploy

### A. Remote Bank Host

- Binary: `build/bank`
- Runs with fixed IP/port (example: `203.0.113.10:3000`)
- Auth file created once on startup: `bank.auth`

### B. Public Frontend

- Build output: `ui/frontend/dist`
- Hosted on any static platform (Nginx, Vercel, Netlify, S3+CloudFront, etc.)
- Must call local backend URL (`http://127.0.0.1:<local-port>`) instead of same-origin `/api`
- For this repo, target URL is `https://guntas-13.github.io/secure-atm/`
- GitHub Pages workflow file: `.github/workflows/ui-gh-pages.yml`

### C. Local Runtime (per user machine)

- Node backend from `ui/backend`
- Local ATM binary (`build/atm` equivalent for user OS)
- Local `bank.auth`
- Config pointing to remote bank host/port

---

## 3) Required Code/Config Adjustments

## 3.1 Frontend API base URL mode

Current frontend uses relative `/api/...` calls. For this deployment, frontend must support explicit API base URL.

Implementation requirement:

- Add env var in frontend build/runtime: `VITE_LOCAL_API_BASE`.
- In `ui/frontend/src/api.js`, resolve endpoint as:
  - `const API_BASE = import.meta.env.VITE_LOCAL_API_BASE || ''`
  - Fetch `${API_BASE}/api/transaction`, etc.

Production value example:

- `VITE_LOCAL_API_BASE=http://127.0.0.1:4000`

---

## 3.2 Local backend CORS allowlist

Because frontend origin is public and backend is localhost, add CORS middleware in backend:

- Allow only your frontend origin(s), e.g. `https://atm.example.com`
- Allow methods: `GET, POST`
- Allow headers: `Content-Type`

Do not use wildcard `*` in production for this model.

---

## 3.3 Local backend config defaults

For each user machine (`ui/backend/.env`):

- `PORT=4000`
- `ATM_BIN=/absolute/path/to/atm`
- `AUTH_FILE=/absolute/path/to/bank.auth`
- `CARD_DIR=/absolute/path/to/card/dir`
- `BANK_HOST=<remote-bank-ip>`
- `BANK_PORT=<remote-bank-port>`

Example:

```env
PORT=4000
ATM_BIN=/Users/alice/secure-atm-runtime/atm
AUTH_FILE=/Users/alice/secure-atm-runtime/bank.auth
CARD_DIR=/Users/alice/secure-atm-runtime/cards
BANK_HOST=203.0.113.10
BANK_PORT=3000
```

---

## 4) Remote Bank Deployment Procedure

1. Provision server (Linux/macOS VM acceptable).
2. Copy `bank` binary to server.
3. Open firewall for chosen bank port (e.g. 3000/TCP).
4. Start bank as service (systemd/supervisor/nohup).

Example command:

```bash
./bank -p 3000 -s bank.auth
```

5. Keep process running continuously.
6. Record public IP and port for all client configs.

---

## 5) Public Frontend Deployment Procedure

1. Build frontend:

```bash
cd ui/frontend
npm install
VITE_LOCAL_API_BASE=http://127.0.0.1:4000 npm run build
```

2. In repository settings -> Pages, set source to **GitHub Actions**.
3. Push changes to `master` under `ui/frontend/` (or trigger workflow manually).
4. Verify browser loads `https://guntas-13.github.io/secure-atm/`.

---

## 6) Local User Runtime Installation Procedure

Each user performs once:

1. Install Node.js (>=18).
2. Place local ATM runtime files:
   - `atm` binary
   - `bank.auth`
   - card directory (for `.card` files)
3. Configure backend `.env` with absolute paths + remote bank IP/port. - Set `CORS_ALLOWED_ORIGINS=https://guntas-13.github.io`
4. Install backend deps and start backend:

```bash
cd ui/backend
npm install
npm start
```

Expected local backend URL:

- `http://127.0.0.1:4000`

5. Open public frontend URL in browser.
6. Submit test transaction.

---

## 7) End-to-End Validation Checklist

1. On bank host: process listening on configured port.
2. On user machine: local backend reachable at `127.0.0.1:4000/api/health`.
3. Browser devtools: API calls go to localhost backend URL.
4. Create/deposit/withdraw/balance all succeed.
5. If `createWithSecret` enabled, returned card secret appears in UI result panel.

---

## 8) Operations Notes

- If backend changes, users update local backend package and restart.
- If ATM binary changes, users replace local binary.
- If bank host/port changes, users update `.env` (`BANK_HOST`, `BANK_PORT`).
- If local backend port changes, rebuild frontend with updated `VITE_LOCAL_API_BASE` or provide runtime config mechanism.

---

## 9) Optional Packaging (Recommended for usability)

To reduce setup friction, package a local "ATM Agent" installer that includes:

- backend code
- ATM binary
- startup script/service
- UI for selecting `bank.auth` path and card directory

Then users only:

1. Install agent
2. Start agent
3. Open public frontend URL

---

## 10) Quick Start Command Summary

### Bank host

```bash
./bank -p 3000 -s bank.auth
```

### User local backend

```bash
cd ui/backend
npm install
npm start
```

### Frontend build for public host

```bash
cd ui/frontend
npm install
VITE_LOCAL_API_BASE=http://127.0.0.1:4000 npm run build
```

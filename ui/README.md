# Secure ATM – Web UI

A single-page browser interface for the ATM client. A thin Node.js/Express backend spawns the existing `atm` CLI binary and returns the result as JSON. The React + Vite frontend provides the user-facing form.

---

## Architecture

```
Browser (React SPA)
      |
      |  POST /api/transaction (JSON)
      V
Node.js backend  ---- spawn(atm, argv) --->  atm binary --- TCP --> bank server
      |                                    |
      |                              reads/writes
      |                           bank.auth  *.card
      |                                    |
      <-- JSON result ----------------------
```

- **Secrets never leave the server.** The auth file and card files are accessed only by the `atm` binary; the browser never sees them.
- **No shell is used.** The backend calls `spawn(atm, argv[])` – each argument is a separate element, eliminating injection risks.
- **Backend binds to 127.0.0.1** – it is reachable only from the same machine.

---

## Prerequisites

| Requirement              | Notes                                  |
| ------------------------ | -------------------------------------- |
| **C++ bank + atm built** | `cd build && make` must have succeeded |
| **Node.js ≥ 18**         | `node --version` to check              |
| **npm**                  | Comes with Node                        |

---

## Quick start

### Run Makefile

```bash
cd secure-atm/ui
make
```

**OR**

### 1. Start the bank server

Open a terminal in `build/`:

```bash
cd secure-atm/build
./bank -p 3000 -s bank.auth
```

Wait for it to print `created` (first run) or stay running silently (subsequent runs).

### 2. Start the backend

```bash
cd secure-atm/ui/backend
cp .env.example .env   # optional: edit paths/port if needed
npm install            # first time only
npm start
```

Expected output:

```
ATM UI backend listening on http://127.0.0.1:4000
  atm binary : /…/secure-atm/build/atm
  auth file  : /…/secure-atm/build/bank.auth
  card dir   : /…/secure-atm/build
  bank       : 127.0.0.1:3000
```

### 3. Open the SPA in your browser

The backend serves the pre-built React app from `ui/frontend/dist/`:

```
http://127.0.0.1:4000
```

If you see "Frontend not built yet", run the build step once:

```bash
cd secure-atm/ui/frontend
npm install   # first time only
npm run build
```

Then refresh the page.

---

## Development mode (hot-reload)

Run the backend and the Vite dev server simultaneously in separate terminals:

```bash
# Terminal 1 – backend
cd secure-atm/ui/backend
npm start

# Terminal 2 – frontend (Vite proxies /api/* to :4000)
cd secure-atm/ui/frontend
npm run dev
# Open: http://localhost:5173
```

---

## Configuration (`.env`)

All settings have sensible defaults pointing at `build/`:

| Variable    | Default (relative to `ui/backend/`) | Description                                 |
| ----------- | ----------------------------------- | ------------------------------------------- |
| `PORT`      | `4000`                              | Port the backend listens on                 |
| `ATM_BIN`   | `../../build/atm`                   | Path to the compiled atm binary             |
| `AUTH_FILE` | `../../build/bank.auth`             | Path to the shared auth file                |
| `CARD_DIR`  | `../../build`                       | Directory where `<account>.card` files live |
| `BANK_HOST` | `127.0.0.1`                         | Default bank IP (overridable per request)   |
| `BANK_PORT` | `3000`                              | Default bank port (overridable per request) |

---

## API reference

### `POST /api/transaction`

Submit an ATM transaction.

**Request body:**

```json
{
  "account": "alice",
  "operation": "balance",
  "amount": "100.00",
  "bankHost": "127.0.0.1",
  "bankPort": 3000
}
```

`amount` is required for `create`, `deposit`, `withdraw`; omit for `balance`.  
`bankHost` and `bankPort` are optional (fall back to config defaults).

**Successful response:**

```json
{ "ok": true, "data": { "account": "alice", "balance": 1000.0 } }
```

**Error response:**

```json
{ "ok": false, "exitCode": 63, "message": "protocol_error" }
```

| Exit code | Meaning                                                            |
| --------- | ------------------------------------------------------------------ |
| `63`      | Network / protocol error (bank unreachable, auth failure, timeout) |
| `255`     | Business error (wrong card, insufficient funds, account exists…)   |

### `GET /api/accounts`

Returns the list of accounts that have a `.card` file in `CARD_DIR`.

```json
{ "ok": true, "accounts": ["alice", "bob"] }
```

### `GET /api/health`

```json
{
  "ok": true,
  "atm": true,
  "auth": true,
  "bankHost": "127.0.0.1",
  "bankPort": 3000
}
```

---

## Project layout

```
ui/
+-- README.md
+-- Makefile
+-- backend/
|   +-- package.json
|   +-- .env.example
|   +-- server.js          Express app + static SPA serving
|   +-- config.js          Env/defaults loader
|   +-- validate.js        Input validation (mirrors C++ ATM rules)
|   +-- runAtm.js          argv builder + child_process.spawn wrapper
+-- frontend/
    +-- package.json
    +-- vite.config.js
    +-- index.html
    +-- src/
        +-- main.jsx
        +-- App.jsx        Single-page UI
        +-- App.css
        +-- api.js         fetch() helpers
```

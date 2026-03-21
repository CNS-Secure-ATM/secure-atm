"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const rateLimit = require("express-rate-limit");

const config = require("./config");
const log = require("./logger");
const { validateTransaction, validateAccountName } = require("./validate");
const { runAtm } = require("./runAtm");

const app = express();
const accountHistory = new Map();
const MAX_HISTORY_PER_ACCOUNT = 100;

function appendHistoryEntry(account, entry) {
  const current = accountHistory.get(account) || [];
  current.push(entry);
  if (current.length > MAX_HISTORY_PER_ACCOUNT) {
    current.splice(0, current.length - MAX_HISTORY_PER_ACCOUNT);
  }
  accountHistory.set(account, current);
}

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: "16kb" }));

// ── Rate limiter ──────────────────────────────────────────────────────────────
const txLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    log.warn("rate limit exceeded", { ip: req.ip });
    res
      .status(429)
      .json({ ok: false, message: "Too many requests, please slow down." });
  },
});

// ── API routes ────────────────────────────────────────────────────────────────

app.get("/api/health", (req, res) => {
  const atmExists = fs.existsSync(config.atmBin);
  const authExists = fs.existsSync(config.authFile);
  if (!atmExists)
    log.warn("health: atm binary not found", { path: config.atmBin });
  if (!authExists)
    log.warn("health: auth file not found", { path: config.authFile });
  res.json({
    ok: true,
    atm: atmExists,
    auth: authExists,
    bankHost: config.bankHost,
    bankPort: config.bankPort,
  });
});

app.get("/api/accounts", (req, res) => {
  try {
    const files = fs.readdirSync(config.cardDir);
    const accounts = files
      .filter((f) => f.endsWith(".card") && f !== ".card")
      .map((f) => f.slice(0, -5));
    res.json({ ok: true, accounts });
  } catch (err) {
    log.error("failed to read card dir", { err: err.message });
    res.json({ ok: true, accounts: [] });
  }
});

app.get("/api/history", (req, res) => {
  const account = String(req.query.account || "").trim();
  if (!account) {
    return res
      .status(400)
      .json({ ok: false, message: "Missing account query parameter" });
  }

  const accountError = validateAccountName(account);
  if (accountError) {
    return res.status(400).json({ ok: false, message: accountError });
  }

  const history = accountHistory.get(account) || [];
  return res.json({ ok: true, account, history });
});

app.post("/api/transaction", txLimiter, async (req, res) => {
  const validationError = validateTransaction(req.body);
  if (validationError) {
    log.warn("transaction rejected", {
      account: req.body?.account,
      operation: req.body?.operation,
      reason: validationError,
    });
    return res.status(400).json({ ok: false, message: validationError });
  }

  const { account, operation } = req.body;
  const result = await runAtm(req.body);

  const historyEntry = {
    timestamp: new Date().toISOString(),
    operation,
    amount: typeof req.body.amount === "string" ? req.body.amount : null,
    ok: result.ok,
    exitCode: result.ok ? 0 : result.exitCode,
    message: result.ok ? "ok" : result.message,
  };
  if (result.ok && result.data && result.data.balance !== undefined) {
    historyEntry.balance = result.data.balance;
  }
  appendHistoryEntry(account, historyEntry);

  if (result.ok) {
    log.info("transaction ok", { account, operation });
    return res.json({ ok: true, data: result.data });
  }

  log.warn("transaction failed", {
    account,
    operation,
    exitCode: result.exitCode,
    message: result.message,
  });

  const status = result.exitCode === 63 ? 502 : 422;
  return res.status(status).json({
    ok: false,
    exitCode: result.exitCode,
    operation,
    message: result.message,
  });
});

// ── Global error handler ──────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  log.error("unhandled error", { err: err.message, status: err.status });
  const status = err.status || err.statusCode || 500;
  res
    .status(status)
    .json({ ok: false, message: err.message || "Internal server error" });
});

// ── Static SPA ────────────────────────────────────────────────────────────────
const spaDir = path.join(__dirname, "..", "frontend", "dist");
if (fs.existsSync(spaDir)) {
  app.use(express.static(spaDir));
  // Only fall back to index.html for extensionless paths (real SPA routes).
  // Requests with a file extension (.js, .css, .png …) that were not found by
  // express.static get a 404 instead of HTML – this prevents browser extensions
  // (React DevTools etc.) from receiving index.html when they fetch their own
  // scripts (utils.js, extensionState.js, heuristicRedefinitions.js, …).
  app.get("*", (req, res) => {
    if (path.extname(req.path)) {
      return res.status(404).end();
    }
    res.sendFile(path.join(spaDir, "index.html"));
  });
} else {
  app.get("/", (req, res) => {
    res.send(
      "<p>Frontend not built yet. Run <code>cd ui/frontend && npm install && npm run build</code>.</p>",
    );
  });
}

// ── Export ────────────────────────────────────────────────────────────────────
module.exports = app;

// ── Start ─────────────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(config.port, "127.0.0.1", () => {
    log.info("server started", {
      url: `http://127.0.0.1:${config.port}`,
      bank: `${config.bankHost}:${config.bankPort}`,
    });
  });
}

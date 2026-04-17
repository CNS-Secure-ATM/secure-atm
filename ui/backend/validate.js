"use strict";

// Lightweight input-shape validation for the Express API layer.
// Business-logic rules (balance limits, account existence, card matching, etc.)
// are enforced exclusively by the ATM binary — the source of truth.
// This module only checks types and bounds so runAtm.js never crashes on bad input.

const VALID_OPERATIONS = new Set(["create", "deposit", "withdraw", "balance"]);

function validateAccountName(account) {
  if (
    typeof account !== "string" ||
    account.length === 0 ||
    account.length > 122
  ) {
    return "Invalid account name";
  }
  return null;
}

/**
 * Returns null on success, or an error string on failure.
 * @param {object} body - parsed request body
 */
function validateTransaction(body) {
  if (!body || typeof body !== "object") {
    return "Invalid request body";
  }

  const {
    account,
    operation,
    amount,
    bankHost,
    bankPort,
    cardSecret,
    createWithSecret,
  } = body;

  // account – must be a non-empty string within spec length
  {
    const accountError = validateAccountName(account);
    if (accountError) return accountError;
  }

  // operation – must be one of the known values
  if (typeof operation !== "string" || !VALID_OPERATIONS.has(operation)) {
    return "Invalid operation (must be one of: create, deposit, withdraw, balance)";
  }

  // amount – required for create/deposit/withdraw, must be a non-empty string
  if (operation !== "balance") {
    if (
      typeof amount !== "string" ||
      amount.length === 0 ||
      amount.length > 20
    ) {
      return "Invalid amount";
    }
  }

  // optional cardSecret – must be a non-empty string if provided
  if (cardSecret !== undefined) {
    if (typeof cardSecret !== "string" || cardSecret.trim().length === 0) {
      return "Invalid card secret";
    }
    if (cardSecret.length > 4096) {
      return "Card secret too long";
    }
  }

  // optional createWithSecret – must be boolean if provided
  if (createWithSecret !== undefined) {
    if (typeof createWithSecret !== "boolean") {
      return "Invalid createWithSecret flag";
    }
  }

  // optional bankHost – must be a string if provided
  if (bankHost !== undefined) {
    if (
      typeof bankHost !== "string" ||
      bankHost.length === 0 ||
      bankHost.length > 15
    ) {
      return "Invalid bank host";
    }
  }

  // optional bankPort – must be a number if provided
  if (bankPort !== undefined) {
    const p = Number(bankPort);
    if (!Number.isInteger(p) || p < 1024 || p > 65535) {
      return "Invalid bank port (must be 1024-65535)";
    }
  }

  return null;
}

module.exports = { validateTransaction, validateAccountName };

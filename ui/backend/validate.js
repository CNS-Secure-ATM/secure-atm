'use strict';

// Mirror the validation rules of the C++ ATM binary exactly so the backend
// rejects bad input before even spawning the process.

const ACCOUNT_RE = /^[_\-\.0-9a-z]{1,122}$/;
const AMOUNT_RE = /^(0|[1-9][0-9]*)\.[0-9]{2}$/;
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const VALID_OPERATIONS = new Set(['create', 'deposit', 'withdraw', 'balance']);

/**
 * Returns null on success, or an error string on failure.
 * @param {object} body - parsed request body
 */
function validateTransaction(body) {
  const { account, operation, amount, bankHost, bankPort } = body;

  // account
  if (typeof account !== 'string' || !ACCOUNT_RE.test(account)) {
    return 'Invalid account name (1-122 chars, lowercase alphanum + _ - .)';
  }
  // Reject path traversal sequences explicitly
  if (account === '.' || account === '..') {
    return 'Invalid account name';
  }

  // operation
  if (typeof operation !== 'string' || !VALID_OPERATIONS.has(operation)) {
    return 'Invalid operation (must be one of: create, deposit, withdraw, balance)';
  }

  // amount – required for create/deposit/withdraw
  if (operation !== 'balance') {
    if (typeof amount !== 'string' || !AMOUNT_RE.test(amount)) {
      return 'Invalid amount format (expected d.dd, e.g. 100.00)';
    }
    const cents = parseCents(amount);
    if (cents === null) {
      return 'Amount out of range';
    }
    if (operation === 'create' && cents < 1000) {
      return 'Initial balance must be at least 10.00';
    }
    if ((operation === 'deposit' || operation === 'withdraw') && cents === 0) {
      return 'Amount must be greater than 0.00';
    }
  }

  // optional bankHost
  if (bankHost !== undefined) {
    if (typeof bankHost !== 'string' || !IP_RE.test(bankHost)) {
      return 'Invalid bank host (must be dotted-decimal IPv4)';
    }
    const octets = bankHost.split('.').map(Number);
    if (octets.some((o) => o < 0 || o > 255)) {
      return 'Invalid bank host (octet out of range)';
    }
  }

  // optional bankPort
  if (bankPort !== undefined) {
    const p = Number(bankPort);
    if (!Number.isInteger(p) || p < 1024 || p > 65535) {
      return 'Invalid bank port (must be 1024-65535)';
    }
  }

  return null;
}

/**
 * Parse "123.45" → 12345 (cents as integer).
 * Returns null if conversion fails or value is too large.
 */
function parseCents(amountStr) {
  const parts = amountStr.split('.');
  if (parts.length !== 2 || parts[1].length !== 2) return null;
  const whole = BigInt(parts[0]);
  const frac = BigInt(parts[1]);
  const cents = whole * 100n + frac;
  // uint64 max is 18446744073709551615; limit to spec's 4294967295.99 (uint32 whole)
  if (cents > 429496729599n) return null;
  return Number(cents);
}

module.exports = { validateTransaction, parseCents };

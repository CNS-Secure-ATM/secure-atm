'use strict';

const { validateTransaction, parseCents } = require('../../validate');

// ── parseCents ────────────────────────────────────────────────────────────────

describe('parseCents', () => {
  test('converts "100.00" → 10000', () => {
    expect(parseCents('100.00')).toBe(10000);
  });

  test('converts "0.01" → 1', () => {
    expect(parseCents('0.01')).toBe(1);
  });

  test('converts "0.00" → 0', () => {
    expect(parseCents('0.00')).toBe(0);
  });

  test('converts "4294967295.99" → max allowed value', () => {
    expect(parseCents('4294967295.99')).toBe(429496729599);
  });

  test('returns null for value above cap', () => {
    expect(parseCents('4294967296.00')).toBeNull();
  });

  test('returns null for missing decimal part', () => {
    expect(parseCents('100')).toBeNull();
  });

  test('returns null for single decimal digit', () => {
    expect(parseCents('100.1')).toBeNull();
  });

  test('returns null for three decimal digits', () => {
    expect(parseCents('100.123')).toBeNull();
  });
});

// ── validateTransaction – account ─────────────────────────────────────────────

describe('validateTransaction – account', () => {
  const base = { account: 'alice', operation: 'balance' };

  test('accepts valid lowercase account', () => {
    expect(validateTransaction(base)).toBeNull();
  });

  test('accepts account with digits and special chars', () => {
    expect(validateTransaction({ ...base, account: 'alice_123.test-account' })).toBeNull();
  });

  test('accepts single-char account', () => {
    expect(validateTransaction({ ...base, account: 'a' })).toBeNull();
  });

  test('accepts 122-char account', () => {
    expect(validateTransaction({ ...base, account: 'a'.repeat(122) })).toBeNull();
  });

  test('rejects empty account', () => {
    expect(validateTransaction({ ...base, account: '' })).not.toBeNull();
  });

  test('rejects 123-char account (too long)', () => {
    expect(validateTransaction({ ...base, account: 'a'.repeat(123) })).not.toBeNull();
  });

  test('rejects uppercase letters', () => {
    expect(validateTransaction({ ...base, account: 'Alice' })).not.toBeNull();
  });

  test('rejects path traversal ".."', () => {
    expect(validateTransaction({ ...base, account: '..' })).not.toBeNull();
  });

  test('rejects "." (single dot)', () => {
    expect(validateTransaction({ ...base, account: '.' })).not.toBeNull();
  });

  test('rejects slash in account name', () => {
    expect(validateTransaction({ ...base, account: 'al/ice' })).not.toBeNull();
  });

  test('rejects account with spaces', () => {
    expect(validateTransaction({ ...base, account: 'al ice' })).not.toBeNull();
  });

  test('rejects missing account field', () => {
    expect(validateTransaction({ operation: 'balance' })).not.toBeNull();
  });
});

// ── validateTransaction – operation ───────────────────────────────────────────

describe('validateTransaction – operation', () => {
  const base = { account: 'alice' };

  test.each(['create', 'deposit', 'withdraw', 'balance'])('accepts operation "%s"', (op) => {
    const amount = op === 'balance' ? undefined : '50.00';
    const body = amount ? { ...base, operation: op, amount } : { ...base, operation: op };
    // create also needs amount >= 10.00
    const finalBody = op === 'create' ? { ...base, operation: op, amount: '10.00' } : body;
    expect(validateTransaction(finalBody)).toBeNull();
  });

  test('rejects unknown operation "transfer"', () => {
    expect(validateTransaction({ ...base, operation: 'transfer', amount: '10.00' })).not.toBeNull();
  });

  test('rejects missing operation', () => {
    expect(validateTransaction({ ...base })).not.toBeNull();
  });
});

// ── validateTransaction – amount ──────────────────────────────────────────────

describe('validateTransaction – amount', () => {
  const base = { account: 'alice' };

  test('accepts valid deposit amount', () => {
    expect(validateTransaction({ ...base, operation: 'deposit', amount: '100.00' })).toBeNull();
  });

  test('accepts minimum create amount 10.00', () => {
    expect(validateTransaction({ ...base, operation: 'create', amount: '10.00' })).toBeNull();
  });

  test('rejects create amount below 10.00', () => {
    expect(validateTransaction({ ...base, operation: 'create', amount: '9.99' })).not.toBeNull();
  });

  test('rejects zero deposit', () => {
    expect(validateTransaction({ ...base, operation: 'deposit', amount: '0.00' })).not.toBeNull();
  });

  test('rejects zero withdraw', () => {
    expect(validateTransaction({ ...base, operation: 'withdraw', amount: '0.00' })).not.toBeNull();
  });

  test('rejects non-numeric amount', () => {
    expect(validateTransaction({ ...base, operation: 'deposit', amount: 'abc' })).not.toBeNull();
  });

  test('rejects amount with only one decimal digit', () => {
    expect(validateTransaction({ ...base, operation: 'deposit', amount: '10.1' })).not.toBeNull();
  });

  test('rejects amount without decimal', () => {
    expect(validateTransaction({ ...base, operation: 'deposit', amount: '100' })).not.toBeNull();
  });

  test('rejects negative amount string', () => {
    expect(validateTransaction({ ...base, operation: 'deposit', amount: '-10.00' })).not.toBeNull();
  });

  test('rejects leading zeros (e.g. "010.00")', () => {
    expect(validateTransaction({ ...base, operation: 'deposit', amount: '010.00' })).not.toBeNull();
  });

  test('missing amount is an error for deposit', () => {
    expect(validateTransaction({ ...base, operation: 'deposit' })).not.toBeNull();
  });

  test('amount is ignored (not required) for balance', () => {
    expect(validateTransaction({ ...base, operation: 'balance' })).toBeNull();
  });
});

// ── validateTransaction – bankHost / bankPort ─────────────────────────────────

describe('validateTransaction – optional bankHost / bankPort', () => {
  const base = { account: 'alice', operation: 'balance' };

  test('accepts valid IPv4 bankHost', () => {
    expect(validateTransaction({ ...base, bankHost: '192.168.1.1' })).toBeNull();
  });

  test('accepts loopback bankHost', () => {
    expect(validateTransaction({ ...base, bankHost: '127.0.0.1' })).toBeNull();
  });

  test('rejects hostname (non-dotted-decimal)', () => {
    expect(validateTransaction({ ...base, bankHost: 'localhost' })).not.toBeNull();
  });

  test('rejects bankHost with out-of-range octet', () => {
    expect(validateTransaction({ ...base, bankHost: '256.0.0.1' })).not.toBeNull();
  });

  test('accepts valid port 3000', () => {
    expect(validateTransaction({ ...base, bankPort: 3000 })).toBeNull();
  });

  test('accepts boundary port 1024', () => {
    expect(validateTransaction({ ...base, bankPort: 1024 })).toBeNull();
  });

  test('accepts boundary port 65535', () => {
    expect(validateTransaction({ ...base, bankPort: 65535 })).toBeNull();
  });

  test('rejects port 1023 (below minimum)', () => {
    expect(validateTransaction({ ...base, bankPort: 1023 })).not.toBeNull();
  });

  test('rejects port 65536 (above maximum)', () => {
    expect(validateTransaction({ ...base, bankPort: 65536 })).not.toBeNull();
  });

  test('rejects non-integer port', () => {
    expect(validateTransaction({ ...base, bankPort: 30.5 })).not.toBeNull();
  });
});

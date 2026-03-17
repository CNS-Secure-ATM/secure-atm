'use strict';

/**
 * E2E / integration tests for the Express API.
 *
 * The real atm binary is NOT invoked here. runAtm is mocked so that the tests
 * cover the full HTTP layer (routing, request validation, response shaping,
 * status codes, headers) without needing the bank server or atm binary to be
 * running.
 *
 * If you want true end-to-end tests that invoke the real binary, run the bank
 * server first, then call the API without mocking runAtm.
 */

const request = require('supertest');

// ── Mock runAtm before requiring server ──────────────────────────────────────

const mockRunAtm = jest.fn();
jest.mock('../../runAtm', () => ({ runAtm: mockRunAtm }));

// ── Import app (no listen() is called when required as a module) ─────────────

let app;
beforeAll(() => {
  app = require('../../server');
});

afterEach(() => {
  mockRunAtm.mockReset();
});

// ── GET /api/health ───────────────────────────────────────────────────────────

describe('GET /api/health', () => {
  test('returns 200 with ok: true', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('includes atm and auth boolean flags', async () => {
    const res = await request(app).get('/api/health');
    expect(typeof res.body.atm).toBe('boolean');
    expect(typeof res.body.auth).toBe('boolean');
  });

  test('includes bankHost and bankPort', async () => {
    const res = await request(app).get('/api/health');
    expect(res.body.bankHost).toBeDefined();
    expect(res.body.bankPort).toBeDefined();
  });
});

// ── GET /api/accounts ─────────────────────────────────────────────────────────

describe('GET /api/accounts', () => {
  test('returns 200 with ok: true and accounts array', async () => {
    const res = await request(app).get('/api/accounts');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(Array.isArray(res.body.accounts)).toBe(true);
  });

  test('account names are strings (no full paths, no .card suffix)', async () => {
    const res = await request(app).get('/api/accounts');
    for (const name of res.body.accounts) {
      expect(typeof name).toBe('string');
      expect(name).not.toContain('/');
      expect(name).not.toContain('.card');
    }
  });
});

// ── POST /api/transaction – input validation (400s) ──────────────────────────

describe('POST /api/transaction – validation errors → 400', () => {
  test('missing account → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ operation: 'balance' });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('invalid account (uppercase) → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'Alice', operation: 'balance' });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('path traversal account ".." → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: '..', operation: 'balance' });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('unknown operation "transfer" → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'transfer', amount: '10.00' });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('missing operation → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice' });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('deposit without amount → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'deposit' });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('deposit with zero amount → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'deposit', amount: '0.00' });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('create with amount below 10.00 → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'create', amount: '9.99' });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('bad bankHost (hostname) → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'balance', bankHost: 'mybank.local' });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('bankPort out of range (1023) → 400', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'balance', bankPort: 1023 });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('oversized body → 413 (express json limit)', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ account: 'alice', operation: 'balance', padding: 'x'.repeat(20_000) }));
    expect(res.status).toBe(413);
  });

  test('validates 400 response shape has ok and message', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'INVALID', operation: 'balance' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('ok', false);
    expect(res.body).toHaveProperty('message');
    expect(typeof res.body.message).toBe('string');
  });
});

// ── POST /api/transaction – successful transactions ───────────────────────────

describe('POST /api/transaction – success (mocked runAtm)', () => {
  test('balance – returns 200 with ok: true and data', async () => {
    mockRunAtm.mockResolvedValue({ ok: true, data: { account: 'alice', balance: 1000.00 } });

    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'balance' });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.data.balance).toBe(1000.00);
  });

  test('deposit – returns 200 with deposit field', async () => {
    mockRunAtm.mockResolvedValue({ ok: true, data: { account: 'alice', deposit: 200.00 } });

    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'deposit', amount: '200.00' });

    expect(res.status).toBe(200);
    expect(res.body.data.deposit).toBe(200.00);
  });

  test('withdraw – returns 200 with withdraw field', async () => {
    mockRunAtm.mockResolvedValue({ ok: true, data: { account: 'alice', withdraw: 50.00 } });

    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'withdraw', amount: '50.00' });

    expect(res.status).toBe(200);
    expect(res.body.data.withdraw).toBe(50.00);
  });

  test('create – returns 200 with initial_balance field', async () => {
    mockRunAtm.mockResolvedValue({ ok: true, data: { account: 'bob', initial_balance: 100.00 } });

    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'bob', operation: 'create', amount: '100.00' });

    expect(res.status).toBe(200);
    expect(res.body.data.initial_balance).toBe(100.00);
  });

  test('runAtm is called with the validated parameters', async () => {
    mockRunAtm.mockResolvedValue({ ok: true, data: { account: 'alice', balance: 0 } });

    await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'balance' });

    expect(mockRunAtm).toHaveBeenCalledTimes(1);
    const callArg = mockRunAtm.mock.calls[0][0];
    expect(callArg.account).toBe('alice');
    expect(callArg.operation).toBe('balance');
  });
});

// ── POST /api/transaction – ATM error cases ───────────────────────────────────

describe('POST /api/transaction – ATM errors (mocked runAtm)', () => {
  test('exit code 63 (protocol error) → 502', async () => {
    mockRunAtm.mockResolvedValue({ ok: false, exitCode: 63, message: 'protocol_error' });

    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'balance' });

    expect(res.status).toBe(502);
    expect(res.body.ok).toBe(false);
    expect(res.body.exitCode).toBe(63);
    expect(res.body.message).toBe('protocol_error');
  });

  test('exit code 255 (business error) → 422', async () => {
    mockRunAtm.mockResolvedValue({ ok: false, exitCode: 255, message: 'transaction_failed' });

    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'balance' });

    expect(res.status).toBe(422);
    expect(res.body.ok).toBe(false);
    expect(res.body.exitCode).toBe(255);
  });

  test('binary not found → 422 with message', async () => {
    mockRunAtm.mockResolvedValue({
      ok: false,
      exitCode: 255,
      message: 'Failed to launch atm binary: spawn ENOENT',
    });

    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'balance' });

    expect(res.status).toBe(422);
    expect(res.body.ok).toBe(false);
    expect(res.body.message).toBeDefined();
  });

  test('error response never exposes auth file path', async () => {
    mockRunAtm.mockResolvedValue({ ok: false, exitCode: 255, message: 'transaction_failed' });

    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'alice', operation: 'balance' });

    const bodyStr = JSON.stringify(res.body);
    // The auth file or card dir path must not leak into the response
    expect(bodyStr).not.toMatch(/bank\.auth/);
    expect(bodyStr).not.toMatch(/\/build\//);
  });
});

// ── Content-type & JSON response headers ─────────────────────────────────────

describe('Response content-type', () => {
  test('/api/health returns application/json', async () => {
    const res = await request(app).get('/api/health');
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });

  test('/api/accounts returns application/json', async () => {
    const res = await request(app).get('/api/accounts');
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });

  test('/api/transaction 400 returns application/json', async () => {
    const res = await request(app)
      .post('/api/transaction')
      .send({ account: 'INVALID', operation: 'balance' });
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });
});

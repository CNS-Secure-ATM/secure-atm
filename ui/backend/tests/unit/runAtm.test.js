'use strict';

const EventEmitter = require('events');

// ── Mock child_process.spawn before requiring runAtm ─────────────────────────

const mockSpawn = jest.fn();
jest.mock('child_process', () => ({ spawn: mockSpawn }));

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Build a fake ChildProcess whose stdout/stderr/close events can be driven
 * from test code via the returned control object.
 */
function makeFakeChild() {
  const stdout = new EventEmitter();
  const stderr = new EventEmitter();
  const proc = new EventEmitter();
  proc.stdout = stdout;
  proc.stderr = stderr;

  const ctrl = {
    emitStdout: (data) => stdout.emit('data', Buffer.from(data)),
    emitStderr: (data) => stderr.emit('data', Buffer.from(data)),
    close: (code) => proc.emit('close', code),
    error: (err) => proc.emit('error', err),
  };

  return { proc, ctrl };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('runAtm', () => {
  let runAtm;

  beforeEach(() => {
    jest.resetModules();
    jest.mock('child_process', () => ({ spawn: mockSpawn }));
    ({ runAtm } = require('../../runAtm'));
  });

  afterEach(() => {
    mockSpawn.mockReset();
  });

  // ── Successful transactions ──────────────────────────────────────────────

  test('balance – returns parsed JSON on exit 0', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'balance' });
    ctrl.emitStdout(JSON.stringify({ account: 'alice', balance: 1500.00 }));
    ctrl.close(0);

    const result = await resultP;
    expect(result.ok).toBe(true);
    expect(result.data).toEqual({ account: 'alice', balance: 1500.00 });
  });

  test('deposit – returns parsed JSON on exit 0', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'deposit', amount: '200.00' });
    ctrl.emitStdout(JSON.stringify({ account: 'alice', deposit: 200.00 }));
    ctrl.close(0);

    const result = await resultP;
    expect(result.ok).toBe(true);
    expect(result.data.deposit).toBe(200.00);
  });

  test('withdraw – returns parsed JSON on exit 0', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'withdraw', amount: '50.00' });
    ctrl.emitStdout(JSON.stringify({ account: 'alice', withdraw: 50.00 }));
    ctrl.close(0);

    const result = await resultP;
    expect(result.ok).toBe(true);
    expect(result.data.withdraw).toBe(50.00);
  });

  test('create – returns parsed JSON on exit 0', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'bob', operation: 'create', amount: '100.00' });
    ctrl.emitStdout(JSON.stringify({ account: 'bob', initial_balance: 100.00 }));
    ctrl.close(0);

    const result = await resultP;
    expect(result.ok).toBe(true);
    expect(result.data.initial_balance).toBe(100.00);
  });

  // ── argv construction ────────────────────────────────────────────────────

  test('balance – builds argv with -g flag', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'balance' });
    ctrl.close(0); // exit without stdout → non-JSON, but argv check is synchronous

    await resultP;
    const argv = mockSpawn.mock.calls[0][1];
    expect(argv).toContain('-g');
    expect(argv).toContain('-a');
    expect(argv[argv.indexOf('-a') + 1]).toBe('alice');
  });

  test('deposit – builds argv with -d and amount', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'deposit', amount: '75.00' });
    ctrl.close(0);
    await resultP;

    const argv = mockSpawn.mock.calls[0][1];
    expect(argv).toContain('-d');
    expect(argv[argv.indexOf('-d') + 1]).toBe('75.00');
  });

  test('withdraw – builds argv with -w and amount', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'withdraw', amount: '25.00' });
    ctrl.close(0);
    await resultP;

    const argv = mockSpawn.mock.calls[0][1];
    expect(argv).toContain('-w');
    expect(argv[argv.indexOf('-w') + 1]).toBe('25.00');
  });

  test('create – builds argv with -n and amount', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'bob', operation: 'create', amount: '100.00' });
    ctrl.close(0);
    await resultP;

    const argv = mockSpawn.mock.calls[0][1];
    expect(argv).toContain('-n');
    expect(argv[argv.indexOf('-n') + 1]).toBe('100.00');
  });

  test('custom bankHost / bankPort are passed into argv', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({
      account: 'alice',
      operation: 'balance',
      bankHost: '10.0.0.2',
      bankPort: 5000,
    });
    ctrl.close(0);
    await resultP;

    const argv = mockSpawn.mock.calls[0][1];
    expect(argv[argv.indexOf('-i') + 1]).toBe('10.0.0.2');
    expect(argv[argv.indexOf('-p') + 1]).toBe('5000');
  });

  test('card file arg is a basename only (no slashes) – ATM filename validator requires this', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'balance' });
    ctrl.close(0);
    await resultP;

    const argv = mockSpawn.mock.calls[0][1];
    const cardFileArg = argv[argv.indexOf('-c') + 1];
    expect(cardFileArg).toBe('alice.card');           // exact basename
    expect(cardFileArg).not.toContain('/');           // no path separator
    expect(cardFileArg).not.toContain('..');          // no traversal
  });

  test('auth file arg is a basename only (no slashes) – ATM filename validator requires this', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'balance' });
    ctrl.close(0);
    await resultP;

    const argv = mockSpawn.mock.calls[0][1];
    const authFileArg = argv[argv.indexOf('-s') + 1];
    expect(authFileArg).not.toContain('/');           // no path separator
    expect(authFileArg).toMatch(/\.auth$/);           // still ends with .auth
  });

  // ── Error cases ──────────────────────────────────────────────────────────

  test('exit code 63 → { ok: false, exitCode: 63, message: "protocol_error" }', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'balance' });
    ctrl.close(63);

    const result = await resultP;
    expect(result.ok).toBe(false);
    expect(result.exitCode).toBe(63);
    expect(result.message).toBe('protocol_error');
  });

  test('exit code 255 → { ok: false, exitCode: 255, message: "transaction_failed" }', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'balance' });
    ctrl.close(255);

    const result = await resultP;
    expect(result.ok).toBe(false);
    expect(result.exitCode).toBe(255);
    expect(result.message).toBe('transaction_failed');
  });

  test('spawn error (binary not found) → ok: false with message', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'balance' });
    ctrl.error(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }));

    const result = await resultP;
    expect(result.ok).toBe(false);
    expect(result.message).toMatch(/Failed to launch atm binary/i);
  });

  test('exit 0 with non-JSON stdout → ok: false', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'balance' });
    ctrl.emitStdout('not json at all');
    ctrl.close(0);

    const result = await resultP;
    expect(result.ok).toBe(false);
    expect(result.message).toMatch(/non-JSON/i);
  });

  test('stdout can arrive in multiple chunks before close', async () => {
    const { proc, ctrl } = makeFakeChild();
    mockSpawn.mockReturnValue(proc);

    const resultP = runAtm({ account: 'alice', operation: 'balance' });
    ctrl.emitStdout('{"account":"alice"');
    ctrl.emitStdout(',"balance":500}');
    ctrl.close(0);

    const result = await resultP;
    expect(result.ok).toBe(true);
    expect(result.data.balance).toBe(500);
  });
});

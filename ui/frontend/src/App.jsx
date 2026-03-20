import { useState, useEffect, useCallback } from 'react';
import { postTransaction, fetchAccounts, fetchHealth } from './api.js';

const OPERATIONS = [
  { value: 'balance', label: 'Get Balance' },
  { value: 'create', label: 'Create Account' },
  { value: 'deposit', label: 'Deposit' },
  { value: 'withdraw', label: 'Withdraw' },
];

const NEEDS_AMOUNT = new Set(['create', 'deposit', 'withdraw']);

/**
 * Map a backend error response to a concise, human-readable message.
 * The backend never leaks sensitive detail, so we enrich based on exitCode + operation.
 */
function friendlyError(result) {
  // Network-level failure (backend not running / fetch threw)
  if (result.networkError) {
    return 'Cannot reach the ATM service. Make sure the backend server is running.';
  }

  const { exitCode, message, operation } = result;

  // Validation errors from backend (400) – message is already descriptive.
  if (!exitCode) return message ?? 'An unknown error occurred.';

  // Exit 63: bank TCP connection failed / auth / timeout.
  if (exitCode === 63) {
    return 'Could not reach the bank server. Check that the bank is running and the host/port are correct.';
  }

  // Exit 255: business-logic rejection.
  if (exitCode === 255) {
    if (message === 'Failed to launch atm binary' || (message && message.startsWith('Failed to launch'))) {
      return 'ATM binary not found or not executable. Run "cd build && make" first.';
    }
    switch (operation) {
      case 'create':
        return 'Account creation failed — the account may already exist or a card file is already present.';
      case 'deposit':
        return 'Deposit failed — account not found or invalid card.';
      case 'withdraw':
        return 'Withdrawal failed — insufficient funds, account not found, or invalid card.';
      case 'balance':
        return 'Balance query failed — account not found or invalid card.';
      default:
        return 'Transaction declined by the bank.';
    }
  }

  return message ?? 'An unexpected error occurred.';
}

function formatResult(data) {
  if (!data) return null;
  const lines = [];
  if (data.account) lines.push({ label: 'Account', value: data.account });
  if (data.balance !== undefined) lines.push({ label: 'Balance', value: `$${Number(data.balance).toFixed(2)}` });
  if (data.initial_balance !== undefined) lines.push({ label: 'Initial Balance', value: `$${Number(data.initial_balance).toFixed(2)}` });
  if (data.deposit !== undefined) lines.push({ label: 'Deposited', value: `$${Number(data.deposit).toFixed(2)}` });
  if (data.withdraw !== undefined) lines.push({ label: 'Withdrawn', value: `$${Number(data.withdraw).toFixed(2)}` });
  return lines;
}

function StatusBadge({ health }) {
  if (!health) return null;
  if (health.networkError) {
    return <span className="status-badge status-err" title="Backend server not reachable">● Offline</span>;
  }
  const allOk = health.ok && health.atm && health.auth;
  const tip = !health.atm
    ? 'atm binary not found (run make)'
    : !health.auth
    ? 'bank.auth file not found'
    : `bank: ${health.bankHost}:${health.bankPort}`;
  return (
    <span className={`status-badge ${allOk ? 'status-ok' : 'status-warn'}`} title={tip}>
      {allOk ? '● Ready' : '● Degraded'}
    </span>
  );
}

export default function App() {
  const [account, setAccount] = useState('');
  const [operation, setOperation] = useState('balance');
  const [amount, setAmount] = useState('');
  const [bankHost, setBankHost] = useState('');
  const [bankPort, setBankPort] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);   // { ok, data?, message?, exitCode? }
  const [health, setHealth] = useState(null);
  const [accounts, setAccounts] = useState([]);

  // Load health + account list on mount
  useEffect(() => {
    fetchHealth().then(setHealth);
    fetchAccounts().then(setAccounts);
  }, []);

  const refreshAccounts = useCallback(() => {
    fetchAccounts().then(setAccounts);
  }, []);

  const needsAmount = NEEDS_AMOUNT.has(operation);

  async function handleSubmit(e) {
    e.preventDefault();
    setResult(null);
    setLoading(true);

    const params = { account: account.trim(), operation };
    if (needsAmount) params.amount = amount.trim();
    if (bankHost.trim()) params.bankHost = bankHost.trim();
    if (bankPort.trim()) params.bankPort = parseInt(bankPort.trim(), 10);

    const res = await postTransaction(params);
    setLoading(false);
    setResult(res);

    // Refresh account list after create so the dropdown stays current.
    if (res.ok && operation === 'create') refreshAccounts();
  }

  const resultLines = result?.ok ? formatResult(result.data) : null;

  return (
    <div className="page">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-inner">
          <div className="logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="2" y="5" width="20" height="14" rx="2" />
              <line x1="2" y1="10" x2="22" y2="10" />
            </svg>
            <span>Secure ATM</span>
          </div>
          <StatusBadge health={health} />
        </div>
      </header>

      {/* ── Main ── */}
      <main className="main">
        <div className="card">
          <h1 className="card-title">ATM Terminal</h1>
          <p className="card-subtitle">Select an operation and fill in the details below.</p>

          <form onSubmit={handleSubmit} noValidate>
            {/* Account */}
            <div className="field">
              <label htmlFor="account">Account Name</label>
              <div className="input-row">
                <input
                  id="account"
                  type="text"
                  placeholder="e.g. alice"
                  value={account}
                  onChange={(e) => setAccount(e.target.value)}
                  required
                  autoComplete="off"
                  spellCheck={false}
                  pattern="[_\-.0-9a-z]{1,122}"
                  title="Lowercase letters, digits, underscores, hyphens, or dots (1-122 chars)"
                />
                {accounts.length > 0 && (
                  <select
                    className="account-picker"
                    value=""
                    onChange={(e) => { if (e.target.value) setAccount(e.target.value); }}
                    aria-label="Pick an existing account"
                    title="Pick an existing account"
                  >
                    <option value="">Existing…</option>
                    {accounts.map((a) => (
                      <option key={a} value={a}>{a}</option>
                    ))}
                  </select>
                )}
              </div>
            </div>

            {/* Operation */}
            <div className="field">
              <label htmlFor="operation">Operation</label>
              <div className="op-grid">
                {OPERATIONS.map((op) => (
                  <label key={op.value} className={`op-tile ${operation === op.value ? 'op-active' : ''}`}>
                    <input
                      type="radio"
                      name="operation"
                      value={op.value}
                      checked={operation === op.value}
                      onChange={() => { setOperation(op.value); setAmount(''); setResult(null); }}
                    />
                    <OperationIcon value={op.value} />
                    <span>{op.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Amount */}
            {needsAmount && (
              <div className="field">
                <label htmlFor="amount">Amount (USD)</label>
                <div className="amount-wrap">
                  <span className="currency-sign">$</span>
                  <input
                    id="amount"
                    type="text"
                    placeholder="0.00"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    required
                    autoComplete="off"
                    inputMode="decimal"
                    pattern="(0|[1-9][0-9]*)\.[0-9]{2}"
                    title="Amount in format: 100.00"
                  />
                </div>
              </div>
            )}

            {/* Advanced (bank host/port) */}
            <div className="advanced-toggle">
              <button type="button" className="link-btn" onClick={() => setShowAdvanced((v) => !v)}>
                {showAdvanced ? '▲ Hide' : '▼ Show'} advanced options
              </button>
            </div>

            {showAdvanced && (
              <div className="advanced-panel">
                <div className="field">
                  <label htmlFor="bankHost">Bank Host</label>
                  <input
                    id="bankHost"
                    type="text"
                    placeholder="127.0.0.1"
                    value={bankHost}
                    onChange={(e) => setBankHost(e.target.value)}
                    autoComplete="off"
                  />
                </div>
                <div className="field">
                  <label htmlFor="bankPort">Bank Port</label>
                  <input
                    id="bankPort"
                    type="number"
                    placeholder="3000"
                    min="1024"
                    max="65535"
                    value={bankPort}
                    onChange={(e) => setBankPort(e.target.value)}
                  />
                </div>
              </div>
            )}

            <button type="submit" className="submit-btn" disabled={loading || !account.trim()}>
              {loading ? <span className="spinner" aria-hidden="true" /> : null}
              {loading ? 'Processing…' : 'Submit'}
            </button>
          </form>

          {/* ── Result ── */}
          {result && (
            <div className={`result-box ${result.ok ? 'result-ok' : 'result-err'}`}>
              {result.ok ? (
                <>
                  <p className="result-heading">Transaction successful</p>
                  {resultLines && (
                    <dl className="result-dl">
                      {resultLines.map(({ label, value }) => (
                        <div key={label} className="result-row">
                          <dt>{label}</dt>
                          <dd>{value}</dd>
                        </div>
                      ))}
                    </dl>
                  )}
                </>
              ) : (
                <>
                  <p className="result-heading">Transaction failed</p>
                  <p className="result-detail">{friendlyError({ ...result, operation })}</p>
                  {result.exitCode !== undefined && (
                    <p className="result-code">Exit {result.exitCode} · {result.message}</p>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </main>

      {/* ── Footer ── */}
      <footer className="footer">
        <p>Secure ATM · Group 13 · CNS Project</p>
      </footer>
    </div>
  );
}

function OperationIcon({ value }) {
  switch (value) {
    case 'balance':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <line x1="18" y1="20" x2="18" y2="10" />
          <line x1="12" y1="20" x2="12" y2="4" />
          <line x1="6" y1="20" x2="6" y2="14" />
        </svg>
      );
    case 'create':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="16" />
          <line x1="8" y1="12" x2="16" y2="12" />
        </svg>
      );
    case 'deposit':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <line x1="12" y1="5" x2="12" y2="19" />
          <polyline points="19 12 12 19 5 12" />
        </svg>
      );
    case 'withdraw':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <line x1="12" y1="19" x2="12" y2="5" />
          <polyline points="5 12 12 5 19 12" />
        </svg>
      );
    default:
      return null;
  }
}

/**
 * Post a transaction to the backend API.
 *
 * @param {object} params
 * @param {string} params.account
 * @param {string} params.operation  'create' | 'deposit' | 'withdraw' | 'balance'
 * @param {string} [params.amount]
 * @param {string} [params.bankHost]
 * @param {number} [params.bankPort]
 * @returns {Promise<{ok: boolean, data?: object, message?: string, exitCode?: number, operation?: string, networkError?: boolean}>}
 */
export async function postTransaction(params) {
  try {
    const res = await fetch("/api/transaction", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
    });
    return res.json();
  } catch {
    return {
      ok: false,
      networkError: true,
      message: "Cannot reach the backend server. Make sure it is running.",
    };
  }
}

/**
 * Fetch the list of accounts that have a .card file on the server.
 * @returns {Promise<string[]>}
 */
export async function fetchAccounts() {
  try {
    const res = await fetch("/api/accounts");
    const json = await res.json();
    return json.accounts ?? [];
  } catch {
    return [];
  }
}

/**
 * Fetch backend health status.
 * @returns {Promise<{ok: boolean, atm?: boolean, auth?: boolean, bankHost?: string, bankPort?: number, networkError?: boolean}>}
 */
export async function fetchHealth() {
  try {
    const res = await fetch("/api/health");
    return res.json();
  } catch {
    return { ok: false, networkError: true };
  }
}

/**
 * Fetch transaction history for one account.
 * @param {string} account
 * @returns {Promise<{ok: boolean, account?: string, history?: Array<object>, message?: string}>}
 */
export async function fetchHistory(account) {
  try {
    const params = new URLSearchParams({ account });
    const res = await fetch(`/api/history?${params.toString()}`);
    return res.json();
  } catch {
    return { ok: false, message: "Cannot reach backend." };
  }
}

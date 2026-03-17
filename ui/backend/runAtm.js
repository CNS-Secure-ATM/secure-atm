'use strict';

const { spawn } = require('child_process');
const path = require('path');
const config = require('./config');
const log = require('./logger');

const EXIT_SUCCESS = 0;
const EXIT_PROTOCOL_ERROR = 63;
const EXIT_OTHER_ERROR = 255;

/**
 * Build the argv array for the atm binary and spawn it.
 *
 * @param {object} params - validated transaction parameters
 * @param {string} params.account
 * @param {string} params.operation  'create' | 'deposit' | 'withdraw' | 'balance'
 * @param {string} [params.amount]
 * @param {string} [params.bankHost]
 * @param {number} [params.bankPort]
 * @returns {Promise<{ok: boolean, data?: object, exitCode?: number, message?: string}>}
 */
function runAtm(params) {
  return new Promise((resolve) => {
    const { account, operation, amount, bankHost, bankPort } = params;

    const host = bankHost || config.bankHost;
    const port = String(bankPort || config.bankPort);

    // the basenames.  Both bank.auth and *.card files live in that directory.
    const cwd = config.cardDir;
    const authBasename = path.basename(config.authFile);
    const safeAccount = path.basename(account);
    const cardBasename = `${safeAccount}.card`;

    // Warn if auth file sits outside cardDir – the ATM will not find it.
    if (config.authFile !== path.join(cwd, authBasename)) {
      log.warn('auth file not in CARD_DIR – ATM may fail', {
        authFile: config.authFile,
        cardDir: cwd,
      });
    }

    const argv = [
      '-s', authBasename,
      '-i', host,
      '-p', port,
      '-a', account,
      '-c', cardBasename,
    ];

    switch (operation) {
      case 'create':   argv.push('-n', amount); break;
      case 'deposit':  argv.push('-d', amount); break;
      case 'withdraw': argv.push('-w', amount); break;
      case 'balance':  argv.push('-g');         break;
      default:
        log.error('unknown operation', { operation });
        return resolve({ ok: false, exitCode: EXIT_OTHER_ERROR, message: 'Unknown operation' });
    }

    let stdout = '';
    let stderr = '';

    const child = spawn(config.atmBin, argv, {
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd,
    });

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    child.on('error', (err) => {
      log.error('atm launch failed', { account, operation, err: err.message });
      resolve({
        ok: false,
        exitCode: EXIT_OTHER_ERROR,
        message: `Failed to launch atm binary: ${err.message}`,
      });
    });

    child.on('close', (code) => {
      if (stderr.trim()) {
        log.warn('atm stderr', { account, operation, output: stderr.trim() });
      }

      if (code === EXIT_SUCCESS) {
        const line = stdout.trim();
        try {
          const data = JSON.parse(line);
          return resolve({ ok: true, data });
        } catch {
          log.error('atm produced non-JSON output', { account, operation, stdout: line });
          return resolve({
            ok: false,
            exitCode: EXIT_OTHER_ERROR,
            message: 'atm produced non-JSON output',
          });
        }
      }

      const message = code === EXIT_PROTOCOL_ERROR ? 'protocol_error' : 'transaction_failed';
      resolve({ ok: false, exitCode: code, message });
    });
  });
}

module.exports = { runAtm };

'use strict';

/**
 * Minimal structured logger.
 *
 * Format:  [ISO-timestamp] LEVEL  message  { ...meta }
 * Levels:  info → stdout,  warn / error → stderr
 *
 * Usage:
 *   const log = require('./logger');
 *   log.info('server started', { port: 4000 });
 *   log.warn('validation failed', { account: 'alice', reason: '...' });
 *   log.error('spawn failed', { err: err.message });
 */

const LEVELS = { info: 'INFO ', warn: 'WARN ', error: 'ERROR' };

function write(stream, level, message, meta) {
  const ts = new Date().toISOString();
  const metaStr = meta && Object.keys(meta).length
    ? '  ' + JSON.stringify(meta)
    : '';
  stream.write(`[${ts}] ${LEVELS[level]}  ${message}${metaStr}\n`);
}

const logger = {
  info:  (msg, meta) => write(process.stdout, 'info',  msg, meta),
  warn:  (msg, meta) => write(process.stderr, 'warn',  msg, meta),
  error: (msg, meta) => write(process.stderr, 'error', msg, meta),
};

module.exports = logger;

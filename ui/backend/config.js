'use strict';

const path = require('path');
require('dotenv').config();

// Absolute path to build/ resolved from this file's location (ui/backend/).
// This is the fallback used when env variables are not set.
const BUILD_DIR = path.resolve(__dirname, process.env.BUILD_DIR || '../../build');



const config = {
  port: parseInt(process.env.PORT || '4000', 10),
  atmBin:   path.resolve(__dirname, process.env.ATM_BIN || '../../build/atm'),
  authFile: path.resolve(__dirname, process.env.AUTH_FILE || '../../build/bank.auth'),
  cardDir:  path.resolve(__dirname, process.env.CARD_DIR || '../../build'),
  bankHost: process.env.BANK_HOST || '127.0.0.1',
  bankPort: parseInt(process.env.BANK_PORT || '3000', 10),
};

console.log(config);
module.exports = config;

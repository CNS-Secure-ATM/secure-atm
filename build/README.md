# Secure ATM System

A secure client-server ATM simulation implementing encrypted communication with mutual authentication.

## Prerequisites

- **C++17** compatible compiler (g++ or clang++)
- **CMake** ≥ 3.10
- **OpenSSL** development libraries
- **POSIX** environment (Linux/macOS)

### Install Dependencies

**macOS:**

```bash
brew install cmake openssl
```

**Ubuntu/Debian:**

```bash
sudo apt-get install cmake libssl-dev build-essential
```

## Build

```bash
cd build
make
```

This produces two executables: `bank` and `atm`.

## Usage

### 1. Start the Bank Server

```bash
./bank [-p <port>] [-s <auth-file>]
```

- `-p <port>`: Port to listen on (default: 3000, range: 1024-65535)
- `-s <auth-file>`: Auth file to create (default: bank.auth)

Example:

```bash
./bank -p 4000 -s mybank.auth
```

### 2. Run ATM Operations

```bash
./atm [-s <auth-file>] [-i <ip>] [-p <port>] [-c <card-file> | -C <card-content-hex>] -a <account> <operation>
```

**Options:**

- `-s <auth-file>`: Auth file (default: bank.auth)
- `-i <ip>`: Bank IP address (default: 127.0.0.1)
- `-p <port>`: Bank port (default: 3000)
- `-c <card-file>`: Card file (default: <account>.card)
- `-C <card-content-hex>`: Direct card content (64 hex chars), use instead of `-c`
- `-a <account>`: Account name (required)
- `-m`: Create mode only; print new card content to stdout JSON instead of writing card file
- `-h` / `--help`: Show usage/help

**Operations:**

- `-n <amount>`: Create new account with initial balance
- `-d <amount>`: Deposit funds
- `-w <amount>`: Withdraw funds
- `-g`: Get balance

**Flag constraints:**

- `-c` and `-C` are mutually exclusive
- `-C` is valid only for `-d`, `-w`, `-g`
- `-m` is valid only with `-n`

**Examples:**

```bash
# Create account with $1000
./atm -s mybank.auth -p 4000 -a alice -n 1000.00

# Create account and print card content to stdout (no .card file written)
./atm -s mybank.auth -p 4000 -a bob -n 1000.00 -m

# Deposit $500
./atm -s mybank.auth -p 4000 -a alice -d 500.00

# Deposit using direct card content instead of card file
./atm -s mybank.auth -p 4000 -a alice -d 500.00 -C <64_hex_card_content>

# Withdraw $200
./atm -s mybank.auth -p 4000 -a alice -w 200.00

# Check balance
./atm -s mybank.auth -p 4000 -a alice -g

# Show help
./atm --help
```

## How It Works

### Security Architecture

1. **Key Derivation**: On startup, bank generates a 256-bit master secret, writing it to the auth file. Both parties use HKDF-SHA256 to derive three keys:
   - `K_enc`: AES-256-GCM encryption key
   - `K_mac`: HMAC-SHA256 authentication key
   - `K_card`: Card secret derivation key

2. **Authentication**: Challenge-response protocol using card secrets:
   - Bank sends random 32-byte challenge
   - ATM computes proof: `HMAC(card_secret, challenge)`
   - Bank verifies proof before processing requests

3. **Encryption**: All messages encrypted with AES-256-GCM:
   - 12-byte random nonce per message
   - 16-byte authentication tag
   - Authenticated encryption prevents tampering

4. **Replay Protection**:
   - Sequence numbers (incrementing counter)
   - Timestamps (validated within window)
   - HMAC over entire frame

5. **Memory Safety**:
   - `SecureBuffer` RAII class wipes sensitive data with `OPENSSL_cleanse()`
   - Stack protector and FORTIFY_SOURCE enabled
   - Input validation prevents buffer overflows

### Protocol Flow

```
Bank                                ATM
  |                                  |
  |<--- TCP Connect -----------------|
  |                                  |
  |---- Challenge (32 bytes) ------->|
  |                                  |
  |<--- Proof + Request (encrypted)--|
  |                                  |
  |--- Response (encrypted) -------->|
  |                                  |
  |<--- Close -----------------------|
```

### Exit Codes

| Code | Meaning                                      |
| ---- | -------------------------------------------- |
| 0    | Success                                      |
| 63   | Protocol error (auth failure, network error) |
| 255  | Other error (validation, business logic)     |

## Input Validation

- **Account**: 1-122 chars, `[a-z0-9_.-]`
- **Filename**: 1-127 chars, `[a-z0-9_.-]`, not `.` or `..`
- **Amount**: `(0|[1-9][0-9]*)\.[0-9]{2}`, range 0.00-4294967295.99
- **Port**: 1024-65535
- **IP**: Valid dotted decimal IPv4

## Clean Up

```bash
cd build
make clean
```

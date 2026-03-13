# Secure ATM System

A secure client-server ATM simulation implementing encrypted communication with mutual authentication.

## Project Structure

```
build/
|-- Makefile              # Build wrapper (run `make` here)
|-- CMakeLists.txt        # CMake build configuration
|-- README.md             # This file
|-- include/
|   |-- common/
|   |   |-- types.hpp     # SecureBuffer (RAII memory wiping), constants
|   |   +-- exitcodes.hpp # Exit codes (0=success, 63=protocol, 255=other)
|   |-- crypto/
|   |   |-- random.hpp    # Cryptographic random number generation
|   |   |-- keys.hpp      # HKDF key derivation
|   |   |-- aes_gcm.hpp   # AES-256-GCM encryption/decryption
|   |   +-- hmac.hpp      # HMAC-SHA256, card secrets
|   |-- protocol/
|   |   |-- framing.hpp   # Length-prefixed message framing
|   |   +-- session.hpp   # Encrypted session management
|   |-- validator/
|   |   +-- validator.hpp # Input validation utilities
|   +-- nlohmann/
|       +-- json.hpp      # JSON library (vendored)
|-- src/
|   |-- crypto/           # Crypto implementation
|   |-- protocol/         # Protocol implementation
|   |-- validator/        # Validation implementation
|   |-- bank/main.cpp     # Bank server
|   +-- atm/main.cpp      # ATM client
+-- tests/
    |-- test_framework.hpp    # Minimal test framework
    |-- test_validator.cpp    # Validator unit tests
    |-- test_crypto.cpp       # Crypto unit tests
    |-- test_protocol.cpp     # Protocol unit tests
    +-- test_integration.sh   # End-to-end integration tests
```

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

## Run Tests

```bash
cd build
make test
```

This runs:

1. **Unit tests** — validator, crypto, and protocol tests
2. **Integration tests** — end-to-end bank/atm scenarios

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
./atm [-s <auth-file>] [-i <ip>] [-p <port>] [-c <card-file>] -a <account> <operation>
```

**Options:**

- `-s <auth-file>`: Auth file (default: bank.auth)
- `-i <ip>`: Bank IP address (default: 127.0.0.1)
- `-p <port>`: Bank port (default: 3000)
- `-c <card-file>`: Card file (default: <account>.card)
- `-a <account>`: Account name (required)

**Operations:**

- `-n <amount>`: Create new account with initial balance
- `-d <amount>`: Deposit funds
- `-w <amount>`: Withdraw funds
- `-g`: Get balance

**Examples:**

```bash
# Create account with $1000
./atm -s mybank.auth -p 4000 -a alice -n 1000.00

# Deposit $500
./atm -s mybank.auth -p 4000 -a alice -d 500.00

# Withdraw $200
./atm -s mybank.auth -p 4000 -a alice -w 200.00

# Check balance
./atm -s mybank.auth -p 4000 -a alice -g
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

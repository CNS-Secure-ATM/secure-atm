# Secure ATM - Design Document

## Table of Contents

1. [System Overview](#1-system-overview)
2. [System Architecture Diagram](#2-system-architecture-diagram)
3. [Layered Architecture](#3-layered-architecture)
4. [Cryptographic Design](#4-cryptographic-design)
5. [Auth File - Channel Authentication](#5-auth-file--channel-authentication)
6. [Card File - Account Authentication](#6-card-file--account-authentication)
7. [Protocol Specification](#7-protocol-specification)
8. [Security Properties at Each Stage](#8-security-properties-at-each-stage)
9. [Program Flow - Bank Server](#9-program-flow--bank-server)
10. [Program Flow - ATM Client](#10-program-flow--atm-client)
11. [Threat Model & Attack Mitigations](#11-threat-model--attack-mitigations)
12. [Design Rationale — Why These Choices, What Could Be Simpler](#12-design-rationale--why-these-choices-what-could-be-simpler)
13. [Project Layout & Build System (C++ / CMake)](#13-project-layout--build-system-c--cmake)
14. [C++ Crypto Libraries & Dependencies](#14-c-crypto-libraries--dependencies)
15. [JSON Output Formatting](#15-json-output-formatting)
16. [Error Handling Summary](#16-error-handling-summary)

---

## 1. System Overview

The system consists of two programs:

| Program | Role                                        | Persistence                                      | Network Role                          |
| ------- | ------------------------------------------- | ------------------------------------------------ | ------------------------------------- |
| `bank`  | Server - maintains in-memory account ledger | Auth file (write-once), no other disk state      | TCP server, binds `0.0.0.0:<port>`    |
| `atm`   | Client - single-shot transaction executor   | Card file (create on `-n`, read-only thereafter) | TCP client, connects to `<ip>:<port>` |

Both share a **pre-shared auth file** (distributed out-of-band over a trusted channel) that bootstraps all session security.

---

## 2. System Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────────┐
│                          TRUSTED CHANNEL (out-of-band)                    │
│                                                                           │
│   bank generates bank.auth ──────copy────────► atm reads bank.auth        │
└───────────────────────────────────────────────────────────────────────────┘

    ┌──────────────────────┐                TCP                ┌───────────────────────┐
    │       ATM Client     │    ◄---------------------------►  │     Bank Server       │
    │                      │        (encrypted channel)        │                       │
    │  ┌────────────────┐  │                                   │  ┌─────────────────┐  │
    │  │  CLI Parser    │  │                                   │  │  TCP Listener   │  │
    │  │  (POSIX args)  │  │                                   │  │  (per-client    │  │
    │  └───────┬────────┘  │                                   │  │   handler)      │  │
    │          │           │                                   │  └────────┬────────┘  │
    │  ┌───────▼────────┐  │                                   │  ┌────────▼────────┐  │
    │  │ Input Validator│  │                                   │  │ Protocol Engine │  │
    │  │ (account, amt, │  │                                   │  │ (decrypt, verif │  │
    │  │  file, port,ip)│  │                                   │  │  MAC, dispatch) │  │
    │  └───────┬────────┘  │                                   │  └────────┬────────┘  │
    │          │           │                                   │           │           │
    │  ┌───────▼────────┐  │      ┌─────────────────────┐      │  ┌────────▼────────┐  │
    │  │ Crypto Layer   │──┼──►   │   NETWORK (MITM)    │  ◄───┼──│ Crypto Layer    │  │
    │  │ • AES-256-GCM  │  │      │    observe/modify   │      │  │ • AES-256-GCM   │  │
    │  │ • HMAC-SHA256  │  │      │    inject msgs      │      │  │ • HMAC-SHA256   │  │
    │  │ • Nonces       │  │      └─────────────────────┘      │  │ • Nonces        │  │
    │  └───────┬────────┘  │                                   │  └────────┬────────┘  │
    │          │           │                                   │           │           │
    │  ┌───────▼────────┐  │                                   │  ┌────────▼────────┐  │
    │  │ Card File I/O  │  │                                   │  │ Account Ledger  │  │
    │  │ (create / read)│  │                                   │  │ (in-memory map) │  │
    │  └────────────────┘  │                                   │  └─────────────────┘  │
    │                      │                                   │                       │
    │  ┌────────────────┐  │                                   │  ┌─────────────────┐  │
    │  │ Auth File      │  │                                   │  │ Auth File       │  │
    │  │ (read-only)    │  │                                   │  │ (write-once)    │  │
    │  └────────────────┘  │                                   │  └─────────────────┘  │
    └──────────────────────┘                                   └───────────────────────┘

         Card File                                                  SIGTERM
    ┌──────────────┐                                           handler for
    │ <acct>.card  │                                           graceful exit
    │ (256-bit     │
    │  secret +    │
    │  account     │
    │  binding)    │
    └──────────────┘
```

---

## 3. Layered Architecture

### Layer 1 - CLI & Input Validation Layer

Responsible for:

- POSIX-compliant argument parsing (supports merged flags like `-ga`, `-i4000`)
- Enforcing input constraints: account name regex, amount format `(0|[1-9][0-9]*)\.[0-9]{2}`, file name regex, port range `[1024, 65535]`, IPv4 format
- Rejecting duplicate flags and invalid combinations
- Exit code 255 on any validation failure (no stdout output)

### Layer 2 - Cryptographic / Protocol Layer

Responsible for:

- Reading the auth file and deriving session keys
- Establishing authenticated-encrypted channels over raw TCP
- Constructing, serialising, encrypting, and MACing protocol messages
- Verifying incoming messages (decrypt → verify MAC → verify nonce freshness)
- Enforcing the 10-second timeout

### Layer 3 - Business Logic Layer

**ATM side:**

- Card file creation (`-n`) or card file validation (all other modes)
- Constructing the transaction request
- Printing the JSON result to stdout

**Bank side:**

- In-memory account ledger (`map<string, uint64>` storing cents)
- Transaction processing: create / deposit / withdraw / get-balance
- Atomicity: changes commit only after full validation; rollback on protocol error
- Printing the JSON result to stdout

### Layer 4 - I/O & Networking Layer

- TCP socket management (connect / bind / listen / accept)
- Buffered read/write with length-prefixed framing
- SIGTERM handling (bank)
- stdout flushing after every line

---

## 4. Cryptographic Design

### 4.1 Key Hierarchy

```
bank.auth (256 bits random)                    <- Master Secret (K_master)
     │
     ├──► HKDF-SHA256(K_master, "enc")         -> K_enc   (256-bit AES key)
     │
     ├──► HKDF-SHA256(K_master, "mac")         -> K_mac   (256-bit HMAC key)
     │
     └──► HKDF-SHA256(K_master, "card")        -> K_card  (256-bit card derivation key)
```

**Why HKDF?** A single high-entropy master secret is expanded into domain-separated keys, preventing related-key attacks. Each derived key has a distinct purpose.

### 4.2 Symmetric Encryption - AES-256-GCM

| Property      | Value                                              |
| ------------- | -------------------------------------------------- |
| Algorithm     | AES-256-GCM (Galois/Counter Mode)                  |
| Key size      | 256 bits                                           |
| Nonce/IV size | 96 bits (12 bytes), randomly generated per message |
| Tag size      | 128 bits (16 bytes)                                |

**Why AES-GCM?** It provides **authenticated encryption with associated data (AEAD)** - delivering confidentiality, integrity, and authentication in a single primitive. The GCM tag serves as an implicit MAC, eliminating the need for a separate HMAC over the ciphertext in the primary encryption path.

### 4.3 HMAC-SHA256 - Message Authentication

Even though AES-GCM provides an authentication tag, we layer an **HMAC-SHA256** over the _entire_ wire frame (including nonce, ciphertext, GCM tag, and sequence number) using `K_mac`. This provides:

- **Double authentication boundary**: Even if a GCM implementation has a subtle bug, the outer HMAC catches tampering.
- **Sequence number binding**: The HMAC covers the sequence number, preventing reorder attacks.

```
Wire Frame:
┌──────────┬───────────┬────────────────────────────────┬────────────┬─────────────┐
│ SeqNo    │ Nonce     │ AES-256-GCM Ciphertext + Tag   │ Timestamp  │ HMAC-SHA256 │
│ (8 bytes)│(12 bytes) │ (variable)                     │ (8 bytes)  │ (32 bytes)  │
└──────────┴───────────┴────────────────────────────────┴────────────┴─────────────┘
                                                                          │
            HMAC covers everything from SeqNo to Timestamp ───────────────┘
```

### 4.4 Nonce / IV Strategy

- **Per-message random nonce** (12 bytes from CSPRNG) for AES-GCM IV
- **Monotonic sequence number** (uint64, starts at 0, increments per message per direction) - prevents replay and reordering
- **Timestamp** (unix epoch, 8 bytes) - used with a tolerance window (±30 seconds) as an additional replay guard

### 4.5 Card File Secrets

```
card_secret = HMAC-SHA256(K_card, account_name)  →  256-bit account-binding token
```

The card file stores this `card_secret`. During a transaction, the ATM sends:

```
card_proof = HMAC-SHA256(card_secret, nonce_from_bank)
```

This is a **challenge-response** protocol: the bank computes the expected `card_proof` from its own `K_card` and the account name, then compares. The actual `card_secret` never traverses the wire.

---

## 5. Auth File - Channel Authentication

### Generation (Bank Startup)

```
1. bank checks auth file does NOT exist → exit 255 if it does
2. K_master = CSPRNG(32 bytes)            // 256 bits of entropy
3. Write K_master (hex or base64 encoded) to auth file
4. Print "created\n" to stdout, flush
```

### Usage (Both Sides)

```
1. Read K_master from auth file
2. Derive K_enc  = HKDF(K_master, salt="secure-atm-enc",  info="enc",  len=32)
3. Derive K_mac  = HKDF(K_master, salt="secure-atm-mac",  info="mac",  len=32)
4. Derive K_card = HKDF(K_master, salt="secure-atm-card", info="card", len=32)
```

### Security Properties Provided

| Property                  | Mechanism                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Mutual Authentication** | Both ATM and Bank derive identical keys from `K_master`; a MITM without the auth file cannot produce valid ciphertexts or MACs |
| **Confidentiality**       | AES-256-GCM encryption with `K_enc` - attacker cannot read message contents                                                    |
| **Integrity**             | GCM tag + outer HMAC-SHA256 with `K_mac` - any bit-flip is detected                                                            |
| **Freshness**             | Per-session random nonces + sequence counters - auth file is tied to a specific bank run                                       |

---

## 6. Card File - Account Authentication

### Creation (ATM `-n` mode)

```
1. ATM sends create-account request to Bank (encrypted)
2. Bank verifies account does not exist, creates it with initial balance
3. Bank responds with SUCCESS + account confirmation
4. ATM computes: card_secret = HMAC-SHA256(K_card, account_name)
5. ATM writes card_secret to <account>.card (or specified card file)
```

### Verification (ATM `-d`, `-w`, `-g` modes)

```
1. ATM reads card_secret from card file
2. ATM connects to Bank; Bank sends a random challenge (32 bytes)
3. ATM computes: card_proof = HMAC-SHA256(card_secret, challenge)
4. ATM sends card_proof along with transaction request
5. Bank independently computes expected card_secret from K_card + account_name
6. Bank computes expected card_proof from expected card_secret + challenge
7. Bank verifies card_proof matches → proceeds; else → protocol_error
```

### Security Properties Provided

| Property                     | Mechanism                                                                                              |
| ---------------------------- | ------------------------------------------------------------------------------------------------------ |
| **Account Binding**          | `card_secret` is derived from `K_card` (in auth file) and account name - cannot be forged without both |
| **No Secret-on-Wire**        | Challenge-response protocol - `card_secret` never transmitted                                          |
| **Replay Prevention**        | Fresh random challenge from Bank each session                                                          |
| **Cross-Account Prevention** | Bob's card yields `HMAC(K_card, "bob")` ≠ `HMAC(K_card, "alice")` - Bob cannot access Alice's account  |

---

## 7. Protocol Specification

### 7.1 Message Format

All messages are length-prefixed (4-byte big-endian length header) followed by the encrypted frame.

```
┌──────────────┬──────────────────────────────────────────────────┐
│ Length (4B)  │ Encrypted Frame (see §4.3 wire frame layout)     │
│ big-endian   │                                                  │
└──────────────┴──────────────────────────────────────────────────┘
```

### 7.2 Plaintext Message Structure (before encryption)

```json
{
  "type": "request" | "response" | "challenge",
  "seq": <uint64>,
  "timestamp": <uint64>,
  "account": "<account_name>",
  "operation": "create" | "deposit" | "withdraw" | "balance",
  "amount": "<amount_in_cents_as_string>",
  "card_proof": "<hex_encoded_hmac>",
  "challenge": "<hex_encoded_random_bytes>",
  "status": "success" | "fail",
  "balance": "<balance_in_cents_as_string>",
  "nonce": "<random_session_nonce>"
}
```

Only relevant fields are present per message type.

### 7.3 Transaction Flow (Create Account `-n`)

```
    ATM                                         BANK
     │                                           │
     │──── TCP Connect ─────────────────────────►│
     │                                           │
     │◄─── Challenge { challenge: R_b,           │
     │      nonce: N_session  }──────────────────│
     │                                           │
     │                                           │  Bank sends random
     │                                           │  challenge R_b
     │                                           │
     │──── Request {                             │
     │       type: "request",                    │
     │       operation: "create",                │
     │       account: "bob",                     │
     │       amount: "100000",                   │  (1000.00 in cents)
     │       nonce: N_atm                        │
     │    } ────────────────────────────────────►│
     │                                           │
     │                                           │  Bank checks:
     │                                           │  - account doesn't exist
     │                                           │  - amount >= 1000 cents
     │                                           │  - creates account
     │                                           │
     │◄─── Response {                            │
     │       status: "success",                  │
     │       account: "bob",                     │
     │       balance: "100000"                   │
     │     } ────────────────────────────────────│
     │                                           │
     │  ATM creates card file                    │  Bank prints JSON
     │  ATM prints JSON                          │
     │                                           │
     │──── TCP Close ───────────────────────────►│
```

### 7.4 Transaction Flow (Deposit / Withdraw / Balance)

```
    ATM                                         BANK
     │                                           │
     │──── TCP Connect ─────────────────────────►│
     │                                           │
     │◄─── Challenge { challenge: R_b  } ────────│
     │                                           │
     │  ATM reads card_secret from card file     │
     │  ATM computes:                            │
     │    card_proof = HMAC(card_secret, R_b)    │
     │                                           │
     │──── Request {                             │
     │       type: "request",                    │
     │       operation: "deposit"/"withdraw"/    │
     │                  "balance",               │
     │       account: "bob",                     │
     │       amount: "10000",                    │  (100.00 in cents)
     │       card_proof: <hex>,                  │
     │       nonce: N_atm                        │
     │    } ────────────────────────────────────►│
     │                                           │
     │                                           │  Bank verifies:
     │                                           │  1. Decrypt + verify MAC
     │                                           │  2. Verify card_proof
     │                                           │  3. Check constraints
     │                                           │  4. Apply transaction
     │                                           │
     │◄─── Response {                            │
     │       status: "success" / "fail",         │
     │       account: "bob",                     │
     │       balance/deposit/withdraw: <value>   │
     │     } ────────────────────────────────────│
     │                                           │
     │  ATM prints JSON (or exits 255 on fail)   │  Bank prints JSON
     │                                           │
     │──── TCP Close ───────────────────────────►│
```

### 7.5 Failure Handling — What Happens When Any Stage Fails

Every stage of the protocol has a defined failure path. The guiding principles are:

1. **Bank never crashes** — any invalid input results in `"protocol_error\n"` on stdout, connection close, and return to the accept loop.
2. **ATM exits with an error code** — `exit(63)` for network/protocol failures, `exit(255)` for local validation failures or a Bank-reported `"fail"` status.
3. **No partial state** — if a failure occurs mid-transaction, the Bank rolls back any tentative changes (or simply never commits them, since changes are applied atomically at the end).
4. **No information leakage** — error messages are generic. The Bank does not tell the ATM _why_ a request failed (missing account vs. wrong card vs. insufficient funds). It just sends `status: "fail"` or closes the connection.

---

#### Stage 1: TCP Connection

```
    ATM                                         BANK
     │                                           │
     │──── TCP Connect (SYN) ──────────────────► │
     │                                           │
     ├─ Connection refused (bank not running)    │
     │    → ATM: exit(63), no stdout             │
     │                                           │
     ├─ Connection timeout (network issue)       │
     │    → ATM: exit(63), no stdout             │
     │                                           │
     ├─ Bank accept() fails (fd exhaustion)      │
     │    → Bank: log nothing, continue loop     │
     │    → ATM: exit(63), no stdout             │
```

| Failure                  | ATM Behaviour         | Bank Behaviour               |
| ------------------------ | --------------------- | ---------------------------- |
| Connection refused       | `exit(63)`, no stdout | N/A (not running or backlog) |
| Connection timeout       | `exit(63)`, no stdout | N/A                          |
| `accept()` error on Bank | `exit(63)`, no stdout | Continue accept loop         |

---

#### Stage 2: Bank Sends Challenge

```
    ATM                                         BANK
     │                                           │
     │   (connected)                             │  Generate R_b = CSPRNG(32)
     │                                           │  Encrypt challenge message
     │                                           │
     │                                           ├─ Encrypt fails (OpenSSL error)
     │                                           │    → Bank: "protocol_error\n"
     │                                           │    → Bank: close connection
     │                                           │
     │◄─── Encrypted Challenge { R_b } ───────── │
     │                                           │
     ├─ Read timeout (10s) before recv           │
     │    → ATM: exit(63), no stdout             │
     │                                           │
     ├─ Decrypt fails (wrong auth file)          │
     │    → ATM: exit(63), no stdout             │
     │                                           │
     ├─ Invalid message structure (bad JSON)     │
     │    → ATM: exit(63), no stdout             │
```

| Failure                         | ATM Behaviour         | Bank Behaviour                        |
| ------------------------------- | --------------------- | ------------------------------------- |
| Bank can't generate/encrypt     | `exit(63)`, no stdout | `"protocol_error\n"`, close, continue |
| ATM recv timeout (10s)          | `exit(63)`, no stdout | Eventually times out too, close       |
| ATM decrypt failure (wrong key) | `exit(63)`, no stdout | Unaware — waits for request           |
| Malformed challenge JSON        | `exit(63)`, no stdout | Unaware — waits for request           |

---

#### Stage 3: ATM Sends Encrypted Request

```
    ATM                                         BANK
     │                                           │
     │  Construct request JSON                   │
     │  Encrypt + HMAC                           │
     │                                           │
     │──── Encrypted Request ──────────────────► │
     │                                           │
     │                                           ├─ Read timeout (10s)
     │                                           │    → Bank: "protocol_error\n"
     │                                           │    → Bank: close, continue loop
     │                                           │
     │                                           ├─ Length prefix > MAX_MSG_SIZE
     │                                           │    → Bank: "protocol_error\n"
     │                                           │    → Bank: close, continue loop
     │                                           │
     │                                           ├─ GCM decrypt fails (bad key/tampered)
     │                                           │    → Bank: "protocol_error\n"
     │                                           │    → Bank: close, continue loop
     │                                           │
     │                                           ├─ Outer HMAC mismatch
     │                                           │    → Bank: "protocol_error\n"
     │                                           │    → Bank: close, continue loop
     │                                           │
     │                                           ├─ Sequence number != expected
     │                                           │    → Bank: "protocol_error\n"
     │                                           │    → Bank: close, continue loop
     │                                           │
     │                                           ├─ Timestamp outside ±30s window
     │                                           │    → Bank: "protocol_error\n"
     │                                           │    → Bank: close, continue loop
     │                                           │
     │                                           ├─ Malformed JSON (missing fields)
     │                                           │    → Bank: "protocol_error\n"
     │                                           │    → Bank: close, continue loop
```

| Failure                           | ATM Behaviour                        | Bank Behaviour                            |
| --------------------------------- | ------------------------------------ | ----------------------------------------- |
| ATM can't encrypt (OpenSSL error) | `exit(255)`, no stdout               | Times out after 10s, `"protocol_error\n"` |
| ATM send fails (broken pipe)      | `exit(63)`, no stdout                | Times out after 10s, `"protocol_error\n"` |
| Bank recv timeout                 | Waiting for response → times out too | `"protocol_error\n"`, close, continue     |
| Length prefix too large           | N/A                                  | `"protocol_error\n"`, close, continue     |
| GCM tag verification fails        | N/A                                  | `"protocol_error\n"`, close, continue     |
| HMAC mismatch                     | N/A                                  | `"protocol_error\n"`, close, continue     |
| Bad sequence number               | N/A                                  | `"protocol_error\n"`, close, continue     |
| Expired timestamp                 | N/A                                  | `"protocol_error\n"`, close, continue     |
| Malformed JSON after decryption   | N/A                                  | `"protocol_error\n"`, close, continue     |

> **Key point:** Every failure at this stage results in the same Bank output: `"protocol_error\n"`. The Bank does not distinguish between an attacker and a buggy ATM. This prevents information leakage about _which_ check failed.

---

#### Stage 4: Bank Validates Business Logic

After successful decryption and frame verification, the Bank validates the transaction semantics:

```
    ATM                                         BANK
     │                                           │
     │                                           │  Decryption + frame OK ✓
     │                                           │
     │                                           ├─ card_proof mismatch (wrong card / wrong account)
     │                                           │    → Bank: "protocol_error\n"
     │                                           │    → Bank: close, continue loop
     │                                           │    → ATM: recv fails or gets no response → exit(63)
     │                                           │
     │                                           ├─ CREATE: account already exists
     │                                           │    → Bank: sends encrypted { status: "fail" }
     │                                           │    → Bank: "protocol_error\n", close
     │                                           │    → ATM: receives "fail" → exit(255)
     │                                           │
     │                                           ├─ CREATE: initial balance < 10.00
     │                                           │    → ATM rejects locally before sending (exit 255)
     │                                           │    → Bank also validates: sends { status: "fail" }
     │                                           │
     │                                           ├─ DEPOSIT/WITHDRAW/BALANCE: account not found
     │                                           │    → Bank: sends encrypted { status: "fail" }
     │                                           │    → Bank: "protocol_error\n", close
     │                                           │    → ATM: receives "fail" → exit(255)
     │                                           │
     │                                           ├─ WITHDRAW: insufficient funds (balance < amount)
     │                                           │    → Bank: sends encrypted { status: "fail" }
     │                                           │    → Bank: "protocol_error\n", close
     │                                           │    → ATM: receives "fail" → exit(255)
     │                                           │
     │                                           ├─ DEPOSIT: amount <= 0 or invalid
     │                                           │    → ATM rejects locally (exit 255)
     │                                           │    → Bank also validates: sends { status: "fail" }
     │                                           │
     │                                           ├─ Amount overflow (balance + deposit > max)
     │                                           │    → Bank: sends encrypted { status: "fail" }
     │                                           │    → Bank: "protocol_error\n", close
     │                                           │    → ATM: receives "fail" → exit(255)
```

| Failure                      | Bank stdout output   | Bank sends to ATM           | ATM exit code | ATM stdout |
| ---------------------------- | -------------------- | --------------------------- | ------------- | ---------- |
| Wrong card_proof             | `"protocol_error\n"` | Nothing (close immediately) | `63`          | None       |
| Account already exists       | `"protocol_error\n"` | `{ status: "fail" }`        | `255`         | None       |
| Account not found            | `"protocol_error\n"` | `{ status: "fail" }`        | `255`         | None       |
| Insufficient funds           | `"protocol_error\n"` | `{ status: "fail" }`        | `255`         | None       |
| Invalid amount (server-side) | `"protocol_error\n"` | `{ status: "fail" }`        | `255`         | None       |
| Balance overflow             | `"protocol_error\n"` | `{ status: "fail" }`        | `255`         | None       |

> **Atomicity guarantee:** The Bank never modifies the ledger until _all_ validations pass. The order is: (1) decrypt + verify frame → (2) verify card_proof → (3) check account exists → (4) check constraints (balance, amount) → (5) **only then** commit the change. If any step fails, the ledger is untouched.

---

#### Stage 5: Bank Sends Response

```
    ATM                                         BANK
     │                                           │
     │                                           │  Transaction committed ✓
     │                                           │  Bank prints JSON to stdout ✓
     │                                           │
     │                                           ├─ Encrypt response fails (OpenSSL error)
     │                                           │    → Bank: close connection (JSON already printed)
     │                                           │    → ATM: recv timeout → exit(63)
     │                                           │    → !! Bank state is committed but ATM doesn't know
     │                                           │
     │                                           ├─ Send fails (broken pipe / ATM disconnected)
     │                                           │    → Bank: close connection (JSON already printed)
     │                                           │    → ATM: exit(63)
     │                                           │    → !! Same inconsistency risk (see note below)
     │                                           │
     │◄─── Encrypted Response ───────────────────│
     │                                           │
     ├─ Recv timeout (10s)                       │
     │    → ATM: exit(63), no stdout             │
     │    → Bank: already printed JSON, done     │
     │                                           │
     ├─ GCM decrypt fails (tampered response)    │
     │    → ATM: exit(63), no stdout             │
     │                                           │
     ├─ HMAC mismatch                            │
     │    → ATM: exit(63), no stdout             │
     │                                           │
     ├─ Bad sequence number                      │
     │    → ATM: exit(63), no stdout             │
     │                                           │
     ├─ Expired timestamp                        │
     │    → ATM: exit(63), no stdout             │
     │                                           │
     ├─ status == "fail"                         │
     │    → ATM: exit(255), no stdout            │
     │                                           │
     ├─ Malformed response JSON                  │
     │    → ATM: exit(63), no stdout             │
```

| Failure                        | ATM Behaviour          | Bank Behaviour                     |
| ------------------------------ | ---------------------- | ---------------------------------- |
| Bank can't encrypt response    | `exit(63)`, no stdout  | Already printed JSON; close        |
| Send fails (broken pipe)       | `exit(63)`, no stdout  | Already printed JSON; close        |
| ATM recv timeout               | `exit(63)`, no stdout  | Already printed JSON; done         |
| ATM decrypt failure (tampered) | `exit(63)`, no stdout  | Already printed JSON; done         |
| ATM HMAC mismatch              | `exit(63)`, no stdout  | Already printed JSON; done         |
| Bad sequence / timestamp       | `exit(63)`, no stdout  | Already printed JSON; done         |
| Response status = `"fail"`     | `exit(255)`, no stdout | Printed `"protocol_error\n"`; done |
| Malformed response JSON        | `exit(63)`, no stdout  | Already printed JSON; done         |

> **Edge case — Bank committed but ATM failed to receive:**
> If the Bank successfully processes a deposit/withdrawal and prints its JSON, but the response never reaches the ATM (network failure, MITM drop), the Bank's ledger reflects the change while the ATM reports failure. This is a **fundamental limitation** of any non-two-phase-commit protocol. The spec's design accepts this: the Bank's ledger is the source of truth, and the ATM is stateless. A subsequent balance check (`-g`) will reveal the actual state.

---

#### Stage 6: ATM Post-Processing

```
    ATM
     │
     │  Response received and validated ✓
     │
     ├─ IF CREATE: write card file
     │    ├─ Card file somehow appeared (race condition)
     │    │    → ATM: exit(255), no stdout
     │    │    → Bank: already committed account (account exists but no card file)
     │    │    → !! Recover: re-run create → Bank returns "fail" (account exists)
     │    │         Must manually resolve (spec doesn't cover this)
     │    │
     │    ├─ Disk full / write error
     │    │    → ATM: exit(255), no stdout
     │    │    → Bank: already committed account
     │    │    → !! Same orphaned-account situation
     │    │
     │    └─ Write succeeds → print JSON, exit(0)
     │
     ├─ IF DEPOSIT/WITHDRAW/BALANCE:
     │    → print JSON, flush stdout, exit(0)
```

| Failure                   | ATM exit | ATM stdout | Consequence                                     |
| ------------------------- | -------- | ---------- | ----------------------------------------------- |
| Card file write fails     | `255`    | None       | Orphaned account on Bank (no card to access it) |
| Card file race (appeared) | `255`    | None       | Same orphaned account                           |
| All OK                    | `0`      | JSON line  | Success                                         |

---

#### 7.5.1 Failure Handling Summary — Complete Decision Table

| Stage           | Error Condition     | Bank stdout       | Bank → ATM  | ATM stdout | ATM exit |
| --------------- | ------------------- | ----------------- | ----------- | ---------- | -------- |
| 1 — TCP Connect | Connection refused  | —                 | —           | —          | `63`     |
| 1 — TCP Connect | Connection timeout  | —                 | —           | —          | `63`     |
| 2 — Challenge   | ATM recv timeout    | —                 | —           | —          | `63`     |
| 2 — Challenge   | ATM decrypt failure | —                 | —           | —          | `63`     |
| 3 — Request     | Bank recv timeout   | `protocol_error`  | —           | —          | `63`     |
| 3 — Request     | GCM/HMAC failure    | `protocol_error`  | —           | —          | `63`     |
| 3 — Request     | Bad seq/timestamp   | `protocol_error`  | —           | —          | `63`     |
| 3 — Request     | Malformed JSON      | `protocol_error`  | —           | —          | `63`     |
| 4 — Validation  | Wrong card_proof    | `protocol_error`  | Close       | —          | `63`     |
| 4 — Validation  | Account conflict    | `protocol_error`  | `{fail}`    | —          | `255`    |
| 4 — Validation  | Insufficient funds  | `protocol_error`  | `{fail}`    | —          | `255`    |
| 5 — Response    | ATM recv timeout    | (already printed) | —           | —          | `63`     |
| 5 — Response    | ATM decrypt failure | (already printed) | —           | —          | `63`     |
| 5 — Response    | status = "fail"     | `protocol_error`  | `{fail}`    | —          | `255`    |
| 6 — Post        | Card write failure  | (already printed) | —           | —          | `255`    |
| ✓ — Success     | All OK              | JSON line         | `{success}` | JSON line  | `0`      |

---

## 8. Security Properties at Each Stage

### 8.1 Connection Establishment

| Property                  | How Achieved                                                                                 |
| ------------------------- | -------------------------------------------------------------------------------------------- |
| **Server Authentication** | ATM encrypts with K_enc derived from auth file; only the real Bank can decrypt               |
| **Client Authentication** | Bank's challenge can only be correctly responded to by an ATM with the auth file             |
| **MITM Prevention**       | Without K_master, attacker cannot decrypt or forge messages; GCM + HMAC detect any tampering |

### 8.2 During Message Exchange

| Property            | How Achieved                                                                  |
| ------------------- | ----------------------------------------------------------------------------- |
| **Confidentiality** | AES-256-GCM encryption - all message content is encrypted                     |
| **Integrity**       | GCM authentication tag (128-bit) + HMAC-SHA256 over entire frame              |
| **Authentication**  | Symmetric keys derived from shared auth file → implicit mutual authentication |
| **Anti-Replay**     | Monotonic sequence numbers + per-message random nonce + timestamp window      |
| **Anti-Reorder**    | Sequence number verified to be exactly previous + 1                           |
| **Freshness**       | Timestamp within ±30s of receiver's clock; random challenge per session       |

### 8.3 Account-Level Operations

| Property                   | How Achieved                                                                  |
| -------------------------- | ----------------------------------------------------------------------------- |
| **Account Authentication** | Card file secret + challenge-response (HMAC-based)                            |
| **Account Isolation**      | Card secret is account-name-specific; Bob's card cannot authenticate as Alice |
| **Balance Integrity**      | All balance changes happen server-side only; ATM has no state                 |
| **Withdrawal Constraint**  | Bank checks `balance >= withdrawal` before committing                         |
| **Atomicity**              | Bank applies changes only after full protocol success; rollback on any error  |

### 8.4 At-Rest Security

| Asset           | Protection                                                                                              |
| --------------- | ------------------------------------------------------------------------------------------------------- |
| **Auth file**   | Contains raw K_master; distributed via trusted out-of-band channel; never transmitted over network      |
| **Card file**   | Contains HMAC-derived secret; meaningful only with correct auth file; new auth file = old cards invalid |
| **Bank memory** | In-memory ledger; no disk persistence between runs                                                      |

---

## 9. Program Flow - Bank Server

```
bank [-p <port>] [-s <auth-file>]

START
  │
  ▼
Parse CLI args (POSIX-compliant)
  │ Invalid? → exit(255)
  ▼
Check auth file does NOT exist
  │ Exists? → exit(255)
  ▼
Generate K_master = CSPRNG(32 bytes)
  │
  ▼
Write K_master to auth file
  │
  ▼
Derive K_enc, K_mac, K_card via HKDF
  │
  ▼
Print "created\n", flush stdout
  │
  ▼
Install SIGTERM handler → sets shutdown flag
  │
  ▼
Bind TCP socket to 0.0.0.0:<port>
  │ Fail? → exit(255)
  ▼
Listen for connections
  │
  ▼
┌──────────────── MAIN LOOP ─────────────────┐
│                                            │
│  Accept TCP connection                     │
│    │                                       │
│    ▼                                       │
│  Spawn handler (or handle serially)        │
│    │                                       │
│    ▼                                       │
│  Generate challenge R_b = CSPRNG(32)       │
│    │                                       │
│    ▼                                       │
│  Send encrypted Challenge message          │
│    │                                       │
│    ▼                                       │
│  Set 10-second read timeout                │
│    │                                       │
│    ▼                                       │
│  Receive + decrypt Request message         │
│    │ Timeout or MAC fail?                  │
│    │   → print "protocol_error\n"          │
│    │   → close connection, continue loop   │
│    ▼                                       │
│  Verify sequence number + timestamp        │
│    │ Invalid? → protocol_error + rollback  │
│    ▼                                       │
│  Dispatch by operation:                    │
│                                            │
│  ┌─ CREATE ─────────────────────────┐      │
│  │ Check account not exists         │      │
│  │ Check balance >= 10.00           │      │
│  │ Create account in ledger         │      │
│  │ Print JSON to stdout             │      │
│  │ Send encrypted success response  │      │
│  └──────────────────────────────────┘      │
│                                            │
│  ┌─ DEPOSIT/WITHDRAW/BALANCE ───────┐      │
│  │ Verify card_proof:               │      │
│  │   expected = HMAC(HMAC(K_card,   │      │
│  │     account), R_b)               │      │
│  │   card_proof == expected?        │      │
│  │ Check account exists             │      │
│  │ Check constraints                │      │
│  │ Apply transaction                │      │
│  │ Print JSON to stdout             │      │
│  │ Send encrypted success response  │      │
│  └──────────────────────────────────┘      │
│                                            │
│  Close connection                          │
│  Loop (check shutdown flag)                │
│                                            │
└────────────────────────────────────────────┘
  │
  ▼ (SIGTERM received)
Close listening socket
exit(0)
```

---

## 10. Program Flow - ATM Client

```
atm [-s <auth-file>] [-i <ip>] [-p <port>] [-c <card>] -a <acct> -n/-d/-w/-g [<amt>]

START
  │
  ▼
Parse CLI args (POSIX-compliant)
  │ Invalid? → exit(255)
  │ Duplicate flags? → exit(255)
  │ Missing -a or mode? → exit(255)
  ▼
Validate all inputs (account name, amount format, file names, port, IP)
  │ Invalid? → exit(255)
  ▼
Read auth file
  │ Cannot open / invalid? → exit(255)
  ▼
Derive K_enc, K_mac, K_card via HKDF
  │
  ▼
┌─ IF mode == CREATE (-n) ─────────────┐
│ Check card file does NOT exist       │
│   Exists? → exit(255)                │
│ Check balance >= 10.00               │
│   Invalid? → exit(255)               │
└───────────────────────┬──────────────┘
                        │
┌─ IF mode != CREATE ───┴──────────────┐
│ Read card file                       │
│   Cannot open? → exit(255)           │
│ Parse card_secret from card file     │
└───────────────────────┬──────────────┘
                        │
  ▼
Connect TCP to <ip>:<port>
  │ Cannot connect? → exit(63)
  ▼
Set 10-second timeout on socket
  │
  ▼
Receive + decrypt Challenge from Bank
  │ Timeout / invalid? → exit(63)
  ▼
Extract challenge R_b
  │
  ▼
┌─ IF mode != CREATE ──────────────────┐
│ card_proof = HMAC(card_secret, R_b)  │
└───────────────────────┬──────────────┘
                        │
  ▼
Construct Request message (JSON)
  │
  ▼
Encrypt with AES-256-GCM, compute outer HMAC
  │
  ▼
Send encrypted Request to Bank
  │
  ▼
Receive + decrypt Response from Bank
  │ Timeout / MAC mismatch? → exit(63)
  ▼
Verify sequence number + timestamp
  │ Invalid? → exit(63)
  ▼
Parse response status
  │
  ├─ status == "fail" → exit(255)
  │
  ▼ status == "success"
  │
  ├─ IF mode == CREATE:
  │    Write card file: card_secret = HMAC(K_card, account)
  │    Print: {"account":"<acct>","initial_balance":<bal>}
  │
  ├─ IF mode == DEPOSIT:
  │    Print: {"account":"<acct>","deposit":<amt>}
  │
  ├─ IF mode == WITHDRAW:
  │    Print: {"account":"<acct>","withdraw":<amt>}
  │
  ├─ IF mode == BALANCE:
  │    Print: {"account":"<acct>","balance":<bal>}
  │
  ▼
Flush stdout
Close TCP connection
exit(0)
```

---

## 11. Threat Model & Attack Mitigations

### 11.1 Attacker Capabilities

Per the spec, the attacker:

- Can **observe** all network traffic between ATM and Bank
- Can **modify** messages in transit
- Can **inject** new messages to either party
- Has access to **source code** but NOT the auth file
- May or may not have access to a card file (depending on scenario)

### 11.2 Attack Mitigation Table

| Attack                          | Description                                     | Mitigation                                                                                                                                                                                |
| ------------------------------- | ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Eavesdropping**               | MITM reads transaction details                  | AES-256-GCM encryption provides **confidentiality**; all message content is encrypted with K_enc derived from auth file                                                                   |
| **Message Tampering**           | MITM modifies ciphertext in transit             | GCM authentication tag (128-bit) + outer HMAC-SHA256 detect any modification; both verify or reject                                                                                       |
| **Replay Attack**               | MITM records and replays a valid transaction    | Monotonic sequence numbers + per-session random challenge + timestamp window; Bank rejects any seen or out-of-order sequence                                                              |
| **Reorder Attack**              | MITM reorders messages                          | Strict sequence number checking: expected = previous + 1                                                                                                                                  |
| **Message Injection**           | MITM crafts and sends arbitrary messages        | Without K_enc and K_mac (derived from auth file), attacker cannot produce valid encrypted+authenticated frames                                                                            |
| **Session Hijacking**           | MITM takes over an established session          | All messages are authenticated; injecting into an existing session requires K_enc + K_mac + correct sequence number                                                                       |
| **Impersonation (Bank)**        | Fake bank responds to ATM                       | ATM verifies responses with K_enc/K_mac; fake bank without auth file cannot produce valid responses                                                                                       |
| **Impersonation (ATM)**         | Fake ATM sends requests to Bank                 | Bank authenticates via encrypted channel (auth file) + card proof (challenge-response); both required                                                                                     |
| **Cross-Account Access**        | Use Bob's card to access Alice's account        | card_secret = HMAC(K_card, account_name); Bob's secret ≠ Alice's secret; Bank verifies card_proof against the claimed account                                                             |
| **Card Forgery**                | Create a fake card file                         | Requires K_card (derived from auth file); attacker without auth file cannot compute valid card_secret                                                                                     |
| **Balance Manipulation**        | Inflate balance or withdraw more than available | All balance state is server-side only; ATM is stateless; Bank enforces `balance >= withdrawal_amount`                                                                                     |
| **Denial of Service**           | Flood bank with connections                     | Bank handles each connection independently; invalid data triggers `protocol_error` but does NOT crash the server; 10-second timeout prevents hanging connections from resource exhaustion |
| **Timing Attack**               | Deduce information from response timing         | Use constant-time comparison for HMAC verification (`CRYPTO_memcmp()` from OpenSSL)                                                                                                       |
| **Overflow/Underflow**          | Malicious amounts cause arithmetic errors       | Store balances in cents as `uint64`; validate all amounts against `[0, 4294967295.99]` range; use checked arithmetic                                                                      |
| **Auth File Reuse**             | Old auth file used with new bank instance       | Bank refuses to start if auth file exists; each run creates a fresh auth file with new K_master                                                                                           |
| **Concurrent Transaction Race** | Two ATMs modify same account simultaneously     | Bank uses mutex/lock per account (or serial processing); atomic read-modify-write with mutex held                                                                                         |

### 11.3 Why Not Asymmetric (Public-Key) Cryptography?

The system already has a **pre-shared secret** (auth file) distributed via a trusted channel. This eliminates the key-distribution problem that public-key cryptography solves. Symmetric-only gives us:

- **Simpler implementation** - fewer moving parts, smaller attack surface
- **Better performance** - AES-GCM is hardware-accelerated on modern CPUs (AES-NI)
- **Sufficient security** - with a 256-bit master secret derived into per-purpose keys via HKDF, we get full confidentiality, integrity, and authentication

Public-key crypto (RSA, ECDH) would be needed if we had to establish a shared secret over an untrusted channel (like TLS handshake), but the auth file already provides this.

---

## 12. Design Rationale — Why These Choices, What Could Be Simpler

This section walks through the reasoning behind each design decision step-by-step, explains where simpler alternatives would suffice, identifies which parts are genuinely essential vs. defence-in-depth, and pays particular attention to **card file uniqueness in a distributed setting** and **why each mechanism exists to counter a specific attack**.

---

### 12.1 The Core Insight: A Pre-Shared Secret Changes Everything

The single most important observation is that we already **have** a pre-shared secret — the auth file, distributed over a trusted out-of-band channel. This eliminates the hardest problem in cryptography (key distribution) and means:

> We do **not** need public-key cryptography (RSA, ECDH, certificates, TLS handshakes). Symmetric crypto alone is sufficient and provably secure.

Step-by-step reasoning:

1. **TLS/HTTPS requires a certificate infrastructure** — the server presents a certificate, signed by a CA, to prove its identity. We have no CA. We have something better: a shared secret that both sides already trust.
2. **Diffie-Hellman key exchange** solves the problem of establishing a shared secret over an insecure channel. We already have one. Using DH would add complexity (group parameter selection, ephemeral key generation, protection against small-subgroup attacks) with zero security benefit.
3. **AES-256 with a pre-shared key** gives us 256-bit symmetric security. To achieve equivalent security with RSA, you would need a 15360-bit key. With ECDH, you would need a P-521 curve. The symmetric path is simpler, faster, and equally secure.

**Verdict:** Symmetric-only design is not a shortcut — it is the _correct_ choice given the threat model.

---

### 12.2 Could We Use Something Even Simpler Than AES-GCM?

Let us examine what is strictly necessary and what is defence-in-depth.

#### What the attacker can do (recap)

The MITM can: **(a)** read all bytes on the wire, **(b)** modify bytes in transit, **(c)** inject entirely new messages, **(d)** replay old messages, **(e)** reorder messages, **(f)** delay or drop messages.

#### Minimal sufficient crypto

| Need                | Minimal solution                    | What we chose                   | Why                                                                |
| ------------------- | ----------------------------------- | ------------------------------- | ------------------------------------------------------------------ |
| Confidentiality (a) | AES-256-CBC + random IV per message | AES-256-GCM                     | GCM gives us authentication for free                               |
| Integrity (b)       | HMAC-SHA256 over plaintext          | GCM tag (128-bit)               | Integrated AEAD is less error-prone than Encrypt-then-MAC manually |
| Anti-forgery (c)    | HMAC-SHA256 with shared key         | GCM tag + shared key            | Same mechanism                                                     |
| Anti-replay (d)     | Sequence numbers OR nonces          | Sequence numbers + random nonce | Belt and suspenders                                                |
| Anti-reorder (e)    | Monotonic sequence counter          | Monotonic sequence counter      | Minimal and sufficient                                             |
| Anti-delay (f)      | 10-second timeout                   | 10-second timeout               | Spec requirement                                                   |

**Could we just use AES-CBC + HMAC-SHA256 (Encrypt-then-MAC)?**

Yes. This is provably secure and was the standard before AEAD modes existed. The steps would be:

1. Encrypt plaintext with AES-256-CBC using a random IV
2. Compute `HMAC-SHA256(K_mac, IV || ciphertext)`
3. Send `IV || ciphertext || HMAC`
4. Receiver: verify HMAC first, then decrypt

This would be perfectly safe. We chose AES-GCM instead because:

- **One primitive, one call** — GCM does encrypt + authenticate in a single pass, reducing implementation surface for bugs
- **Associated data** — GCM's AAD input lets us bind the sequence number and metadata to the ciphertext without encrypting them
- **Performance** — GCM is a single-pass stream mode; CBC requires padding and multi-block processing

**Could we skip encryption entirely and just use HMAC?**

If we only cared about authentication and integrity (not confidentiality), we could send `plaintext || HMAC-SHA256(K_mac, plaintext)`. The attacker could _read_ balances and transaction amounts but could not forge or replay. However, the spec says the MITM can "observe" traffic and we should protect customer information, so **confidentiality is required**. Plain HMAC alone is insufficient.

#### The outer HMAC — overkill or justified?

Our wire frame has an HMAC-SHA256 _over_ the already-authenticated GCM ciphertext. Is this redundant?

**Strictly speaking, yes.** AES-GCM's authentication tag already provides integrity and authentication. The outer HMAC is defence-in-depth:

- It protects against hypothetical GCM implementation bugs (nonce-reuse catastrophes, tag truncation bugs)
- It binds the unencrypted header fields (sequence number, timestamp) into the authentication even if someone forgets to put them in GCM's AAD
- It costs ~200ns per message — negligible for a protocol that does 1-3 messages per connection

**A simpler design could drop the outer HMAC entirely and just use AES-GCM with the sequence number + timestamp as AAD.** This is what TLS 1.3 does. Our design keeps the outer HMAC as a safety net, but it is not strictly necessary.

---

### 12.3 Card File Uniqueness — The Key Design Problem

> **The central challenge:** Every card file must be unique per account, unforgeable without the auth file, and must work in a distributed system where multiple ATMs might exist.

#### Why not just store a random token?

**Naive approach:** On account creation, the bank generates `random_token = CSPRNG(32)`, stores it in its ledger, and sends it to the ATM to write into the card file. For future transactions, the ATM sends the token, and the bank compares it against its stored copy.

This works but has a critical problem:

1. **The token traverses the wire during creation** — the MITM sees `random_token` in the encrypted message. If the MITM later compromises the encryption (e.g., through a vulnerability), they have the card secret.
2. **The bank must store the token** — the bank ledger now holds sensitive card data. If the bank process memory is dumped (core dump, crash report), all card secrets are exposed.
3. **No mathematical binding** — the token is just random bytes. There is no way to verify, from the token alone, which account it belongs to. If an attacker swaps card files between accounts, the bank must do a lookup.

#### Our approach: Deterministic derivation via HMAC

```
card_secret = HMAC-SHA256(K_card, account_name)
```

Step-by-step reasoning for why this is superior:

**Step 1 — Uniqueness is mathematical, not random.**
HMAC-SHA256 is a PRF (pseudorandom function). For two different account names `A ≠ B`, the outputs `HMAC(K, A) ≠ HMAC(K, B)` with overwhelming probability (collision resistance of SHA-256: $2^{128}$ security). No coordination or database lookup is needed — uniqueness is guaranteed by the math.

**Step 2 — The bank never stores card secrets.**
The bank only stores `K_card` (derived from the auth file). Given any account name, it can recompute `HMAC(K_card, account_name)` on the fly. This means:

- Zero additional per-account storage for card validation
- No card secrets in memory to leak
- If the bank is restarted with the same auth file (hypothetically), all cards still work

**Step 3 — The card secret never crosses the wire.**
The ATM computes `card_secret` locally using `K_card` (derived from the auth file it already has). The bank computes the same `card_secret` independently. Neither side ever transmits it. What crosses the wire is only `card_proof = HMAC(card_secret, challenge)` — a one-time derivative that is useless after the session.

**Step 4 — Account binding is intrinsic.**
If Bob tries to use his card for Alice's account:

- Bob's card contains `HMAC(K_card, "bob")`
- He claims to be Alice and sends `card_proof = HMAC(HMAC(K_card, "bob"), challenge)`
- Bank computes expected: `HMAC(HMAC(K_card, "alice"), challenge)`
- These differ → rejected

There is no way to repurpose one card for another account without knowing `K_card`, which requires the auth file.

**Step 5 — Works in a distributed system with no coordination.**
If there were multiple bank servers (not required by the spec, but for robustness):

- Every server with the same auth file derives the same `K_card`
- Every server computes the same `card_secret` for the same account
- Card files work transparently across servers
- **No replication of card databases, no distributed consensus needed**

This is a major advantage over the random-token approach, which would require synchronising the token across replicas.

#### Could we use an even simpler card file scheme?

**Scheme A — Just store the account name in the card file:**
The card file says `account=bob`. The ATM reads it, sends it to the bank. The bank checks it matches.

_Problem:_ If the attacker obtains one card file, they learn the scheme and can forge cards for any account by just writing a file with a different name. There is no secret.

**Scheme B — Store `SHA-256(account_name)` in the card file:**
Better — the attacker must know the account name to create a card. But SHA-256 has no key; anyone can compute it. If the attacker knows the account name (which they might — it's sent in the request), they can forge the card.

**Scheme C — Store `HMAC(K_card, account_name)` (our choice):**
The keyed HMAC means the attacker needs `K_card` (derived from the auth file, which they don't have) to forge any card. Even knowing the account name and the format, they cannot compute the correct HMAC output. This is the simplest scheme that provides unforgeability.

**Scheme D — Store a random token + server-side lookup (naive approach above):**
More complex than Scheme C with **worse** properties (token on wire, server must store, no intrinsic binding). Scheme C dominates it.

**Conclusion:** Scheme C (HMAC-based) is both the simplest secure scheme and the most elegant for distribution. Anything simpler either leaks information or is forgeable. Anything more complex adds no security.

---

### 12.4 Step-by-Step: Why Each Anti-MITM Decision Was Made

Let's walk through the protocol and at each stage ask: _what attack does this step prevent?_ and _what's the simplest thing that works?_

#### Step 1: Bank sends encrypted Challenge to ATM

```
Bank → ATM: E(K_enc, { type: "challenge", challenge: R_b })
```

**What it prevents:**

- **Spoofing (fake bank):** Only the real bank has `K_enc`. A fake bank cannot produce a valid encrypted message. The ATM tries to decrypt — if it fails, `exit(63)`. MITM cannot impersonate the bank.

**Why a challenge?**

- `R_b` is 32 random bytes, fresh per connection. This becomes the seed for the card-proof challenge-response. Without it, the ATM's proof would be static (same every time), enabling replay.

**Could this be simpler?**

- We could skip the challenge and have the ATM prove itself with a timestamp-based proof instead: `HMAC(card_secret, current_time)`. But clocks can drift, and an attacker with a 30-second window could replay within that window. A server-generated random challenge has exactly zero replay window.

#### Step 2: ATM sends encrypted Request with card_proof

```
ATM → Bank: E(K_enc, { type: "request", operation: "withdraw",
             account: "bob", amount: "5000",
             card_proof: HMAC(card_secret, R_b) })
```

**What it prevents:**

- **Eavesdropping:** Encrypted — MITM cannot read the transaction details
- **Forgery:** MITM cannot create a valid encrypted frame without `K_enc`
- **Account spoofing:** `card_proof` is bound to both the card secret (which the attacker doesn't have) and the fresh challenge `R_b` (which changes every session)
- **Cross-account attack:** Bob's `card_secret ≠` Alice's `card_secret`, so Bob's proof will fail for Alice's account

**Could this be simpler?**

- If we didn't have the card file requirement, we could omit `card_proof` entirely and rely only on the auth file for authentication. But the spec requires that "only a customer with a correct card file" can access their account. The HMAC-based challenge-response is the minimal way to prove card possession without sending the card secret.

#### Step 3: Bank validates, applies transaction, responds

```
Bank → ATM: E(K_enc, { status: "success", account: "bob", withdraw: 50.00 })
```

**What it prevents:**

- **Response forgery:** MITM cannot craft a fake "success" response to trick the ATM into thinking the transaction succeeded (or a fake "fail" to make the ATM show an error when it shouldn't)
- **Balance leakage:** The response is encrypted, so the MITM cannot learn the resulting balance

**Could this be simpler?**

- We could send an unencrypted success/fail flag. But then the MITM learns whether the transaction succeeded, which leaks information (e.g., repeated withdrawals until failure reveals the balance). Encrypting the response is necessary.

#### Step 4: Sequence numbers on every message

**What they prevent:**

- **Replay:** MITM records message #1 from a previous session. In a new session, sequence numbers start at 0 again, but the challenge `R_b` is different, so the replayed `card_proof` is invalid. Even within a session, replaying message #1 when the bank expects message #2 is rejected.
- **Reordering:** If the protocol had 4 messages and the MITM swapped messages 2 and 3, the sequence check catches it immediately.

**Could this be simpler?**

- For a protocol with only 3 messages (challenge, request, response), reordering is barely possible — there's only one message per direction after the challenge. The sequence number is almost overkill here. But it costs 8 bytes per message and is trivial to implement, so it's cheap insurance for protocol extensions.

#### Step 5: Timestamps

**What they prevent:**

- **Cross-session replay with stolen sequence state:** Even if an attacker somehow reset the sequence counter, a message from 10 minutes ago would have an expired timestamp.
- **Stale connection attacks:** A MITM holds a connection open for hours, then replays it. The timestamp catches it.

**Could this be simpler?**

- Honestly, with fresh random challenges per session and sequence numbers, timestamps are the most expendable. They add a ±30s tolerance window which requires roughly synchronized clocks. In this system (ATM and bank on the same machine or LAN), clocks are synchronized, so the cost is low. But **if we had to simplify, timestamps would be the first thing to drop.**

---

### 12.5 Defending Against DoS and DDoS — Practical Measures

The spec says: _"bank will continue running no matter what data its connected clients might send."_ Here is how we handle resource exhaustion:

#### Attack: Connection Flooding

A MITM opens thousands of TCP connections to the bank.

**Defence — 10-second absolute timeout per connection:**
Every connection has a 10-second hard deadline. After 10 seconds, the bank closes it and prints `protocol_error`. This bounds the maximum resource consumption:

- At any given moment, the bank can have at most `N` open connections, each holding one socket and a small buffer
- After 10 seconds they are force-closed, so the steady-state is bounded

**Why not rate limiting?**
The spec doesn't mention it, and the attacker operates at the network level — IP-based rate limiting is irrelevant when the MITM controls the network. The 10-second timeout is the primary defence.

#### Attack: Malformed Data Flood

MITM sends garbage bytes to every connection.

**Defence — Fail-fast on decryption:**
The first thing the bank does after receiving data is decrypt + verify the GCM tag. Random garbage:

1. Will not have a valid 4-byte length prefix (likely a ridiculous length → reject immediately)
2. If the length is plausible, the GCM tag will not verify → `protocol_error`, close, move on
3. The bank **never** parses untrusted plaintext. It only processes data after successful authenticated decryption.

This means garbage processing costs: one `read()`, one length check, at most one AES-GCM decrypt attempt (~microseconds), then close. The bank is back to accepting new connections immediately.

#### Attack: Slowloris (Slow Data Send)

MITM opens a connection and sends one byte per second to keep it alive.

**Defence — 10-second total timeout, not per-read:**
The timeout starts when the connection is accepted, not when data starts arriving. After 10 seconds total, the connection is killed regardless of how much data has been received. Slowloris is neutralised.

#### Attack: Valid-Looking but Semantically Invalid Requests

MITM cannot create valid encrypted messages (no auth file), so this attack is only possible from a compromised ATM.

**Defence — Server-side validation of every field:**
Even after successful decryption, the bank validates:

- Account name format and existence
- Amount format and range
- Card proof correctness
- Operation legality (e.g., sufficient balance)

Any failure → send encrypted failure response, close connection. The bank does not crash.

#### Attack: Memory Exhaustion via Huge Messages

MITM sends a 4-byte length prefix indicating a 4GB message.

**Defence — Maximum message size cap:**
The bank reads the 4-byte length prefix first. If it exceeds a reasonable maximum (e.g., 8 KB — no valid message should be larger), the bank immediately closes the connection. It never allocates the buffer.

---

### 12.6 Summary: Minimum Viable Security vs. Our Design

| Component      | Minimum that works                    | Our design                           | Delta                                    |
| -------------- | ------------------------------------- | ------------------------------------ | ---------------------------------------- |
| Encryption     | AES-256-CBC + HMAC (Encrypt-then-MAC) | AES-256-GCM (AEAD)                   | Simpler API, same security               |
| Message auth   | HMAC-SHA256 over plaintext            | GCM tag + outer HMAC                 | Outer HMAC is optional safety net        |
| Key derivation | Use K_master directly for everything  | HKDF → K_enc, K_mac, K_card          | Prevents related-key attacks; essential  |
| Card file      | HMAC(K_card, account)                 | Same                                 | Already minimal                          |
| Card proof     | Send card_secret directly             | HMAC(card_secret, challenge)         | Avoids putting secret on wire; essential |
| Anti-replay    | Fresh random challenge per session    | Challenge + seq numbers + timestamps | Seq# and timestamps are defence-in-depth |
| Anti-DoS       | 10-second timeout + max message size  | Same + message-size cap              | Already minimal                          |

The bold conclusion: **the design uses exactly one step above the proven minimum at each layer.** The outer HMAC and timestamps could be dropped with no loss of provable security. Everything else is necessary.

---

## 13. Project Layout & Build System (C++ / CMake)

### 13.1 Directory Structure

```
secure-atm/
├── build/
│   ├── CMakeLists.txt                # Top-level CMake build (produces atm & bank)
│   ├── Makefile                      # Wrapper: just calls cmake --build
│   │
│   ├── include/
│   │   ├── crypto/
│   │   │   ├── keys.hpp              # HKDF key derivation from K_master
│   │   │   ├── aes_gcm.hpp           # AES-256-GCM encrypt / decrypt
│   │   │   ├── hmac.hpp              # HMAC-SHA256 (card proof, outer MAC)
│   │   │   └── random.hpp            # CSPRNG wrappers (nonce, challenge gen)
│   │   │
│   │   ├── protocol/
│   │   │   ├── message.hpp           # Message types & JSON serialization
│   │   │   ├── framing.hpp           # Length-prefixed framing (read/write)
│   │   │   ├── session.hpp           # Encrypted session: send/recv with seq#
│   │   │   └── timeout.hpp           # 10-second deadline management
│   │   │
│   │   ├── validator/
│   │   │   ├── account.hpp           # Account name validation
│   │   │   ├── amount.hpp            # Currency amount parsing & validation
│   │   │   ├── filename.hpp          # File name validation
│   │   │   ├── network.hpp           # IPv4 address & port validation
│   │   │   └── args.hpp              # POSIX CLI argument parser (getopt)
│   │   │
│   │   ├── bank/
│   │   │   ├── server.hpp            # TCP server (bind/listen/accept)
│   │   │   ├── handler.hpp           # Per-connection handler (protocol engine)
│   │   │   ├── ledger.hpp            # In-memory account store (std::mutex)
│   │   │   └── authfile.hpp          # Auth file generation
│   │   │
│   │   ├── atm/
│   │   │   ├── client.hpp            # TCP client (connect, protocol exec)
│   │   │   ├── cardfile.hpp          # Card file read/write
│   │   │   └── authfile.hpp          # Auth file reading & validation
│   │   │
│   │   └── common/
│   │       ├── exitcodes.hpp         # Exit code constants (0, 63, 255)
│   │       └── types.hpp             # Shared typedefs (e.g., Cents = uint64_t)
│   │
│   ├── src/
│   │   ├── crypto/
│   │   │   ├── keys.cpp              # HKDF implementation via OpenSSL EVP
│   │   │   ├── aes_gcm.cpp           # AES-256-GCM using EVP_EncryptInit_ex
│   │   │   ├── hmac.cpp              # HMAC-SHA256 using EVP_MAC (OpenSSL 3.x)
│   │   │   └── random.cpp            # RAND_bytes() wrappers
│   │   │
│   │   ├── protocol/
│   │   │   ├── message.cpp           # JSON serialization (nlohmann/json)
│   │   │   ├── framing.cpp           # 4-byte length-prefix read/write
│   │   │   ├── session.cpp           # Encrypt-then-send / recv-then-decrypt
│   │   │   └── timeout.cpp           # setsockopt SO_RCVTIMEO / SO_SNDTIMEO
│   │   │
│   │   ├── validator/
│   │   │   ├── account.cpp           # Regex: [_\-\.0-9a-z]{1,122}
│   │   │   ├── amount.cpp            # Parse (0|[1-9][0-9]*)\.[0-9]{2}
│   │   │   ├── filename.cpp          # Regex: [_\-\.0-9a-z]{1,127}, not . or ..
│   │   │   ├── network.cpp           # Dotted-decimal IPv4 + port 1024-65535
│   │   │   └── args.cpp              # getopt() based POSIX arg parser
│   │   │
│   │   ├── bank/
│   │   │   ├── main.cpp              # Bank entry point & CLI
│   │   │   ├── server.cpp            # TCP listener, accept loop, SIGTERM
│   │   │   ├── handler.cpp           # Dispatch: create/deposit/withdraw/balance
│   │   │   ├── ledger.cpp            # std::unordered_map + std::mutex
│   │   │   └── authfile.cpp          # CSPRNG → write auth file
│   │   │
│   │   └── atm/
│   │       ├── main.cpp              # ATM entry point & CLI
│   │       ├── client.cpp            # Connect, challenge-response, transact
│   │       ├── cardfile.cpp          # Create / read card file
│   │       └── authfile.cpp          # Read & validate auth file
│   │
│   └── third_party/
│       └── nlohmann/
│           └── json.hpp              # Header-only JSON library (vendored)
```

### 13.2 CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.14)
project(secure-atm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
add_compile_options(-Wall -Wextra -Wpedantic -O2)

# Find OpenSSL (required)
find_package(OpenSSL REQUIRED)

# Find Threads (for std::mutex, std::thread)
find_package(Threads REQUIRED)

# Include paths
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party
)

# Shared library (common code compiled once, linked to both)
set(COMMON_SOURCES
    src/crypto/keys.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/hmac.cpp
    src/crypto/random.cpp
    src/protocol/message.cpp
    src/protocol/framing.cpp
    src/protocol/session.cpp
    src/protocol/timeout.cpp
    src/validator/account.cpp
    src/validator/amount.cpp
    src/validator/filename.cpp
    src/validator/network.cpp
    src/validator/args.cpp
)

add_library(common STATIC ${COMMON_SOURCES})
target_link_libraries(common
    PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads
)

# ATM executable
add_executable(atm
    src/atm/main.cpp
    src/atm/client.cpp
    src/atm/cardfile.cpp
    src/atm/authfile.cpp
)
target_link_libraries(atm PRIVATE common)

# Bank executable
add_executable(bank
    src/bank/main.cpp
    src/bank/server.cpp
    src/bank/handler.cpp
    src/bank/ledger.cpp
    src/bank/authfile.cpp
)
target_link_libraries(bank PRIVATE common)

# Install both binaries into the build directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})
```

### 13.3 Wrapper Makefile (for spec compliance)

The spec requires running `make` in the `build/` directory. This thin wrapper invokes CMake:

```makefile
# build/Makefile — invoked by the grader as: cd build && make

.PHONY: all clean

all:
	@mkdir -p _build && cd _build && cmake .. -DCMAKE_BUILD_TYPE=Release && $(MAKE)
	@cp _build/atm . 2>/dev/null || true
	@cp _build/bank . 2>/dev/null || true

clean:
	@rm -rf _build atm bank
```

This ensures `make` produces `atm` and `bank` directly in `build/` as required, while CMake manages the actual compilation.

### 13.4 Build Instructions

```bash
# From the repository root:
cd build
make          # invokes CMake under the hood
./bank -s bank.auth &
./atm -s bank.auth -a bob -n 1000.00
```

Alternatively, for development:

```bash
cd build
mkdir -p _build && cd _build
cmake .. -DCMAKE_BUILD_TYPE=Debug    # Debug build with symbols
make -j$(nproc)
```

---

## 14. C++ Crypto Libraries & Dependencies

### 14.1 OpenSSL — Primary Crypto Provider

All cryptographic operations use **OpenSSL** (`libssl` + `libcrypto`), which is pre-installed on virtually all Linux distributions and macOS (via Homebrew/system). On Ubuntu/Debian: `apt install libssl-dev`. CMake's `find_package(OpenSSL REQUIRED)` handles detection.

| Purpose               | OpenSSL API                                                                         | Header               |
| --------------------- | ----------------------------------------------------------------------------------- | -------------------- |
| AES-256-GCM encrypt   | `EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), ..., key, iv)`                          | `<openssl/evp.h>`    |
| AES-256-GCM decrypt   | `EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), ..., key, iv)` + `EVP_CTRL_GCM_SET_TAG` | `<openssl/evp.h>`    |
| HMAC-SHA256           | `HMAC(EVP_sha256(), key, key_len, data, data_len, out, &out_len)`                   | `<openssl/hmac.h>`   |
| HKDF (extract+expand) | `EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, ...)` + `EVP_PKEY_derive(...)` (OpenSSL 1.1.0+) | `<openssl/kdf.h>`    |
| CSPRNG                | `RAND_bytes(buf, len)`                                                              | `<openssl/rand.h>`   |
| Constant-time compare | `CRYPTO_memcmp(a, b, len)`                                                          | `<openssl/crypto.h>` |
| Secret cleanup        | `OPENSSL_cleanse(buf, len)`                                                         | `<openssl/crypto.h>` |

### 14.2 nlohmann/json — JSON Serialization

We vendor the single header `nlohmann/json.hpp` (v3.x) into `third_party/nlohmann/`. It is header-only, so it requires no separate compilation or linking — just `#include <nlohmann/json.hpp>`.

**Why not manual formatting?** JSON is simple enough to format by hand with `printf`, but `nlohmann/json` gives us:

- Correct escaping of special characters in account names
- Easy number formatting control
- Parse/validation for protocol messages if needed
- Zero runtime dependency (compiled into the binary)

### 14.3 POSIX / System Libraries

| Purpose               | API                                                             | Header                             |
| --------------------- | --------------------------------------------------------------- | ---------------------------------- |
| TCP sockets           | `socket()`, `bind()`, `listen()`, `accept()`, `connect()`       | `<sys/socket.h>`, `<netinet/in.h>` |
| IP address conversion | `inet_pton()`                                                   | `<arpa/inet.h>`                    |
| Socket timeouts       | `setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, ...)`                  | `<sys/socket.h>`                   |
| Signal handling       | `sigaction(SIGTERM, ...)`                                       | `<signal.h>`                       |
| File I/O              | `std::ifstream`, `std::ofstream` or `open()`/`read()`/`write()` | `<fstream>` or `<fcntl.h>`         |
| CLI argument parsing  | `getopt()` (POSIX)                                              | `<unistd.h>`                       |
| Threading / Mutex     | `std::thread`, `std::mutex`                                     | `<thread>`, `<mutex>`              |
| Output flushing       | `std::cout << std::flush` or `fflush(stdout)`                   | `<iostream>` or `<cstdio>`         |

All of the above are available on any POSIX-compliant system with a C++17 compiler.

### 14.4 Secret Lifetime Management in C++

C++ gives us **explicit control** over secret lifetime, which is critical for a security-sensitive application:

```cpp
// 1. Zero secrets immediately after use
uint8_t key[32];
// ... use key ...
OPENSSL_cleanse(key, sizeof(key));   // guaranteed not optimised away

// 2. RAII wrapper for automatic cleanup
class SecureBuffer {
    std::vector<uint8_t> data_;
public:
    ~SecureBuffer() { OPENSSL_cleanse(data_.data(), data_.size()); }
    // ...
};

// 3. Constant-time comparison (prevents timing attacks)
if (CRYPTO_memcmp(computed_mac, received_mac, 32) != 0) {
    // MAC mismatch → protocol_error
}
```

Unlike garbage-collected languages, C++ guarantees that `OPENSSL_cleanse` runs deterministically in the destructor — no secret data lingers in memory waiting for GC.

---

## 15. JSON Output Formatting

All JSON must be printed on a single line followed by `\n`, with explicit `fflush(stdout)` (or `std::cout << std::flush`).

### Precision Rules

Amounts are stored internally as **cents** (`uint64`). When formatting for output:

```
internal_cents = 100000  →  "1000"      (no trailing .00 needed if cents == 0)
internal_cents = 6310    →  "63.1"      (strip trailing zero: 63.10 → 63.1)
internal_cents = 4363    →  "43.63"
internal_cents = 10      →  "0.1"       (0.10 → 0.1)
```

The JSON number format follows standard JSON: no trailing zeros after decimal point, no unnecessary decimal point.

### Examples

```json
{"account":"55555","initial_balance":10.00}
{"account":"55555","deposit":20.00}
{"account":"55555","withdraw":15.00}
{"account":"55555","balance":43.63}
```

> Note: In the spec examples, `10.00` appears with trailing zeros for `initial_balance`. Follow the exact format shown in the spec examples. With `nlohmann/json`, use `json::number_float_t` for amounts. For custom formatting, write a helper that converts cents to the correct JSON number representation (e.g., `100000` cents → `1000`, `6310` cents → `63.1`). Avoid `double` arithmetic for balance tracking — only use `double` at the JSON output stage.

---

## 16. Error Handling Summary

| Situation                           | ATM Behavior                          | Bank Behavior                                          |
| ----------------------------------- | ------------------------------------- | ------------------------------------------------------ |
| Invalid CLI args                    | exit(255), no stdout                  | exit(255), no stdout                                   |
| Auth file missing/invalid           | exit(255)                             | exit(255) if already exists at startup                 |
| Card file missing (non-create mode) | exit(255)                             | N/A                                                    |
| Card file exists (create mode)      | exit(255)                             | N/A                                                    |
| Cannot connect to bank              | exit(63)                              | N/A                                                    |
| Protocol error (decrypt/MAC fail)   | exit(63)                              | Print `protocol_error\n`, rollback                     |
| 10-second timeout                   | exit(63)                              | Print `protocol_error\n`, rollback                     |
| Account not found                   | exit(255)                             | Send fail response                                     |
| Card proof mismatch                 | exit(255)                             | Send fail response (or protocol_error)                 |
| Insufficient balance (withdraw)     | exit(255)                             | Send fail response                                     |
| Account already exists (create)     | exit(255)                             | Send fail response                                     |
| Amount <= 0 (deposit/withdraw)      | exit(255) (pre-validated client-side) | Also verified server-side                              |
| Balance < 10.00 (create)            | exit(255) (pre-validated client-side) | Also verified server-side                              |
| SIGTERM received                    | N/A                                   | Clean exit(0)                                          |
| Malformed client data               | N/A                                   | `protocol_error\n`, close connection, continue serving |

---

## Appendix A - Auth File Format

```
Base64-encoded 256-bit random key (44 characters + newline)
Example: dGhpcyBpcyBhIDI1Ni1iaXQgcmFuZG9tIGtleQ==
```

Alternatively, hex-encoded (64 characters). Base64 is more compact.

## Appendix B - Card File Format

```
Base64-encoded 256-bit HMAC (44 characters + newline)
```

The card file contains exactly `HMAC-SHA256(K_card, account_name)` encoded in base64. No other metadata is stored to minimize information leakage.

## Appendix C - Internal Amount Representation

To avoid floating-point precision issues, all amounts are stored as **unsigned 64-bit integers representing cents**:

```
Input: "1000.00"  →  Internal: 100000 (cents)
Input: "63.10"    →  Internal: 6310 (cents)
Input: "0.01"     →  Internal: 1 (cent)
```

This ensures exact arithmetic for all financial operations. The bound of `4294967295.99` on input amounts means a single transaction is at most `429496729599` cents, well within `uint64` range. Accumulated balances can grow beyond this limit without overflow risk (uint64 max ≈ 1.8 × 10¹⁹).

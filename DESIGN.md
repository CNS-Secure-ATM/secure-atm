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
13. [Project Layout - Go](#13-project-layout--go)
14. [Project Layout - C++](#14-project-layout--c)
15. [Crypto Library Discussion](#15-crypto-library-discussion)
16. [JSON Output Formatting](#16-json-output-formatting)
17. [Error Handling Summary](#17-error-handling-summary)

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

    ┌──────────────────────┐          TCP / TLS-like           ┌───────────────────────┐
    │       ATM Client     │    ◄══════════════════════════►   │     Bank Server       │
    │                      │       (encrypted channel)         │                       │
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
bank.auth (256 bits random)                    ← Master Secret (K_master)
     │
     ├──► HKDF-SHA256(K_master, "enc")         → K_enc   (256-bit AES key)
     │
     ├──► HKDF-SHA256(K_master, "mac")         → K_mac   (256-bit HMAC key)
     │
     └──► HKDF-SHA256(K_master, "card")        → K_card  (256-bit card derivation key)
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
| **Timing Attack**               | Deduce information from response timing         | Use constant-time comparison for HMAC verification (`crypto/subtle.ConstantTimeCompare` in Go, `CRYPTO_memcmp` in OpenSSL)                                                                |
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

## 13. Project Layout - Go

```
secure-atm/
├── build/
│   ├── Makefile                  # Builds atm and bank binaries
│   ├── go.mod                    # Go module definition
│   ├── go.sum
│   │
│   ├── cmd/
│   │   ├── atm/
│   │   │   └── main.go           # ATM entry point, CLI parsing
│   │   └── bank/
│   │       └── main.go           # Bank entry point, CLI parsing
│   │
│   ├── internal/
│   │   ├── crypto/
│   │   │   ├── keys.go           # HKDF key derivation from K_master
│   │   │   ├── aes_gcm.go        # AES-256-GCM encrypt / decrypt
│   │   │   ├── hmac.go           # HMAC-SHA256 (card proof, outer MAC)
│   │   │   └── random.go         # CSPRNG wrappers (nonces, challenges)
│   │   │
│   │   ├── protocol/
│   │   │   ├── message.go        # Message types, serialization (JSON)
│   │   │   ├── framing.go        # Length-prefixed framing (read/write)
│   │   │   ├── session.go        # Encrypted session: send/recv with seq#
│   │   │   └── timeout.go        # 10-second deadline management
│   │   │
│   │   ├── validator/
│   │   │   ├── account.go        # Account name validation
│   │   │   ├── amount.go         # Currency amount parsing & validation
│   │   │   ├── filename.go       # File name validation
│   │   │   ├── network.go        # IPv4 address & port validation
│   │   │   └── args.go           # POSIX CLI argument parsing
│   │   │
│   │   ├── bank/
│   │   │   ├── server.go         # TCP listener, accept loop, SIGTERM
│   │   │   ├── handler.go        # Per-connection handler (protocol engine)
│   │   │   ├── ledger.go         # In-memory account map with mutex
│   │   │   └── authfile.go       # Auth file generation
│   │   │
│   │   ├── atm/
│   │   │   ├── client.go         # TCP connect, protocol execution
│   │   │   ├── cardfile.go       # Card file read/write
│   │   │   └── authfile.go       # Auth file reading & validation
│   │   │
│   │   └── json/
│   │       └── output.go         # JSON formatting with full precision
│   │
│   └── pkg/
│       └── exitcodes/
│           └── codes.go          # Exit code constants (0, 63, 255)
```

### Makefile (Go)

```makefile
.PHONY: all clean

all: atm bank

atm:
	go build -o atm ./cmd/atm

bank:
	go build -o bank ./cmd/bank

clean:
	rm -f atm bank
```

### Go Crypto Libraries

| Purpose               | Package                                  |
| --------------------- | ---------------------------------------- |
| AES-256-GCM           | `crypto/aes` + `crypto/cipher` (stdlib)  |
| HMAC-SHA256           | `crypto/hmac` + `crypto/sha256` (stdlib) |
| HKDF                  | `golang.org/x/crypto/hkdf`               |
| CSPRNG                | `crypto/rand` (stdlib)                   |
| Constant-time compare | `crypto/subtle` (stdlib)                 |

> **Note**: `golang.org/x/crypto/hkdf` is the only external dependency. Alternatively, HKDF can be implemented manually (it's ~30 lines using HMAC-SHA256).

---

## 14. Project Layout - C++

```
secure-atm/
├── build/
│   ├── Makefile                  # Builds atm and bank binaries
│   │
│   ├── include/
│   │   ├── crypto/
│   │   │   ├── keys.hpp          # HKDF key derivation
│   │   │   ├── aes_gcm.hpp       # AES-256-GCM encrypt / decrypt
│   │   │   ├── hmac.hpp          # HMAC-SHA256
│   │   │   └── random.hpp        # CSPRNG wrappers
│   │   │
│   │   ├── protocol/
│   │   │   ├── message.hpp       # Message types, JSON serialization
│   │   │   ├── framing.hpp       # Length-prefixed framing
│   │   │   ├── session.hpp       # Encrypted session management
│   │   │   └── timeout.hpp       # Socket timeout management
│   │   │
│   │   ├── validator/
│   │   │   ├── account.hpp       # Account name validation
│   │   │   ├── amount.hpp        # Currency amount parsing
│   │   │   ├── filename.hpp      # File name validation
│   │   │   ├── network.hpp       # IPv4 & port validation
│   │   │   └── args.hpp          # POSIX CLI argument parser
│   │   │
│   │   ├── bank/
│   │   │   ├── server.hpp        # TCP server
│   │   │   ├── handler.hpp       # Connection handler
│   │   │   ├── ledger.hpp        # In-memory account store
│   │   │   └── authfile.hpp      # Auth file generation
│   │   │
│   │   ├── atm/
│   │   │   ├── client.hpp        # TCP client
│   │   │   ├── cardfile.hpp      # Card file I/O
│   │   │   └── authfile.hpp      # Auth file reading
│   │   │
│   │   └── common/
│   │       ├── json.hpp          # JSON output (or use nlohmann/json)
│   │       └── exitcodes.hpp     # Exit code constants
│   │
│   ├── src/
│   │   ├── crypto/
│   │   │   ├── keys.cpp
│   │   │   ├── aes_gcm.cpp
│   │   │   ├── hmac.cpp
│   │   │   └── random.cpp
│   │   │
│   │   ├── protocol/
│   │   │   ├── message.cpp
│   │   │   ├── framing.cpp
│   │   │   ├── session.cpp
│   │   │   └── timeout.cpp
│   │   │
│   │   ├── validator/
│   │   │   ├── account.cpp
│   │   │   ├── amount.cpp
│   │   │   ├── filename.cpp
│   │   │   ├── network.cpp
│   │   │   └── args.cpp
│   │   │
│   │   ├── bank/
│   │   │   ├── main.cpp          # Bank entry point
│   │   │   ├── server.cpp
│   │   │   ├── handler.cpp
│   │   │   ├── ledger.cpp
│   │   │   └── authfile.cpp
│   │   │
│   │   └── atm/
│   │       ├── main.cpp          # ATM entry point
│   │       ├── client.cpp
│   │       ├── cardfile.cpp
│   │       └── authfile.cpp
│   │
│   └── third_party/
│       └── nlohmann/
│           └── json.hpp          # Header-only JSON library (optional)
```

### Makefile (C++)

```makefile
CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -Iinclude
LDFLAGS  := -lssl -lcrypto -lpthread

ATM_SRC  := $(wildcard src/atm/*.cpp src/crypto/*.cpp src/protocol/*.cpp src/validator/*.cpp)
BANK_SRC := $(wildcard src/bank/*.cpp src/crypto/*.cpp src/protocol/*.cpp src/validator/*.cpp)

ATM_OBJ  := $(ATM_SRC:.cpp=.o)
BANK_OBJ := $(BANK_SRC:.cpp=.o)

.PHONY: all clean

all: atm bank

atm: $(ATM_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

bank: $(BANK_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f atm bank $(ATM_OBJ) $(BANK_OBJ)
```

### C++ Crypto Libraries

| Purpose               | Library / API                                                                                      |
| --------------------- | -------------------------------------------------------------------------------------------------- |
| AES-256-GCM           | OpenSSL `EVP_aes_256_gcm()` via `EVP_EncryptInit_ex` / `EVP_DecryptInit_ex`                        |
| HMAC-SHA256           | OpenSSL `HMAC()` with `EVP_sha256()`                                                               |
| HKDF                  | OpenSSL 1.1.0+ `EVP_PKEY_derive` with `EVP_PKEY_HKDF` or manual HKDF (extract + expand using HMAC) |
| CSPRNG                | OpenSSL `RAND_bytes()`                                                                             |
| Constant-time compare | OpenSSL `CRYPTO_memcmp()`                                                                          |
| JSON                  | `nlohmann/json` (header-only, no build dependency) or manual formatting                            |
| Networking            | POSIX sockets (`<sys/socket.h>`, `<arpa/inet.h>`)                                                  |
| Signal handling       | `<signal.h>` with `sigaction()` for SIGTERM                                                        |
| Threading (optional)  | `<pthread.h>` or `std::thread` for concurrent connections                                          |

> **OpenSSL** (`libssl`, `libcrypto`) is typically pre-installed on Linux systems and available via `apt install libssl-dev`. This keeps the build offline-compatible as required.

---

## 15. Crypto Library Discussion

### Go: Standard Library + `x/crypto`

**Pros:**

- `crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/sha256`, `crypto/rand`, `crypto/subtle` are all in Go's standard library
- Only `golang.org/x/crypto/hkdf` is external (can be vendored for offline builds)
- Memory-safe language eliminates buffer overflow vulnerabilities
- Garbage collector simplifies secret cleanup (though you should zero secrets explicitly with a `defer`)
- Static linking produces a single binary - easy deployment

**Cons:**

- No hardware-accelerated AES-GCM on all platforms (though Go does use AES-NI when available)
- GC may leave secret residue in memory (mitigatable with explicit zeroing)

### C++: OpenSSL

**Pros:**

- Battle-tested, FIPS-validated cryptographic implementations
- Hardware acceleration (AES-NI) is automatic
- Fine-grained memory control - can explicitly `memset`/`OPENSSL_cleanse` secrets
- Widely available on target systems

**Cons:**

- Manual memory management increases risk of leaks and use-after-free
- API is verbose and error-prone (EVP interface)
- Must link against `libssl` and `libcrypto` (usually available on submission system)
- Need careful error handling for every OpenSSL call

### Recommendation

| Criterion             | Go                      | C++                   |
| --------------------- | ----------------------- | --------------------- |
| Development speed     | ✅ Faster               | Slower                |
| Memory safety         | ✅ GC + bounds checking | Manual (risk of CVEs) |
| Crypto API ergonomics | ✅ Clean, idiomatic     | Verbose EVP API       |
| Performance           | Good (AES-NI supported) | ✅ Slightly better    |
| Binary deployment     | ✅ Static binary        | Need libssl on target |
| Secret cleanup        | Explicit zero needed    | ✅ `OPENSSL_cleanse`  |

**For this project, Go is recommended** due to faster development, memory safety, and minimal external dependencies.

---

## 16. JSON Output Formatting

All JSON must be printed on a single line followed by `\n`, with explicit `fflush(stdout)` / `os.Stdout.Sync()`.

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

> Note: In the spec examples, `10.00` appears with trailing zeros for `initial_balance`. Follow the exact format shown in the spec examples. Some JSON libraries output `10` instead of `10.00` - match the spec output format precisely. The safest approach is to format the number such that the JSON encoder outputs it as-is (e.g., use `float64` in Go with `json.Marshal`, which outputs `1000` for `1000.0` and `63.1` for `63.1`).

---

## 17. Error Handling Summary

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

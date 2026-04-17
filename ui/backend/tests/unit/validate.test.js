"use strict";

const { validateTransaction, validateAccountName } = require("../../validate");

// validate.js is a lightweight shape/type checker.
// All business-logic validation is done by the ATM binary.

// ── validateTransaction – account ─────────────────────────────────────────────

describe("validateTransaction – account", () => {
  const base = { account: "alice", operation: "balance" };

  test("accepts valid account", () => {
    expect(validateTransaction(base)).toBeNull();
  });

  test("accepts single-char account", () => {
    expect(validateTransaction({ ...base, account: "a" })).toBeNull();
  });

  test("accepts 122-char account", () => {
    expect(
      validateTransaction({ ...base, account: "a".repeat(122) }),
    ).toBeNull();
  });

  test('accepts "." as valid account name per spec', () => {
    expect(validateTransaction({ ...base, account: "." })).toBeNull();
  });

  test('accepts ".." as valid account name per spec', () => {
    expect(validateTransaction({ ...base, account: ".." })).toBeNull();
  });

  test("rejects empty account", () => {
    expect(validateTransaction({ ...base, account: "" })).not.toBeNull();
  });

  test("rejects 123-char account (too long)", () => {
    expect(
      validateTransaction({ ...base, account: "a".repeat(123) }),
    ).not.toBeNull();
  });

  test("rejects missing account field", () => {
    expect(validateTransaction({ operation: "balance" })).not.toBeNull();
  });

  test("rejects numeric account", () => {
    expect(validateTransaction({ ...base, account: 123 })).not.toBeNull();
  });
});

// ── validateTransaction – operation ───────────────────────────────────────────

describe("validateTransaction – operation", () => {
  const base = { account: "alice" };

  test.each(["create", "deposit", "withdraw", "balance"])(
    'accepts operation "%s"',
    (op) => {
      const amount = op === "balance" ? undefined : "50.00";
      const body = amount
        ? { ...base, operation: op, amount }
        : { ...base, operation: op };
      expect(validateTransaction(body)).toBeNull();
    },
  );

  test("rejects unknown operation", () => {
    expect(
      validateTransaction({ ...base, operation: "transfer", amount: "10.00" }),
    ).not.toBeNull();
  });

  test("rejects missing operation", () => {
    expect(validateTransaction({ ...base })).not.toBeNull();
  });

  test("rejects numeric operation", () => {
    expect(validateTransaction({ ...base, operation: 42 })).not.toBeNull();
  });
});

// ── validateTransaction – amount ──────────────────────────────────────────────

describe("validateTransaction – amount", () => {
  const base = { account: "alice" };

  test("accepts string amount for deposit", () => {
    expect(
      validateTransaction({ ...base, operation: "deposit", amount: "100.00" }),
    ).toBeNull();
  });

  test("amount not required for balance", () => {
    expect(validateTransaction({ ...base, operation: "balance" })).toBeNull();
  });

  test("rejects missing amount for deposit", () => {
    expect(
      validateTransaction({ ...base, operation: "deposit" }),
    ).not.toBeNull();
  });

  test("rejects numeric amount (must be string)", () => {
    expect(
      validateTransaction({ ...base, operation: "deposit", amount: 100 }),
    ).not.toBeNull();
  });

  test("rejects empty string amount", () => {
    expect(
      validateTransaction({ ...base, operation: "deposit", amount: "" }),
    ).not.toBeNull();
  });
});

// ── validateTransaction – bankHost / bankPort ─────────────────────────────────

describe("validateTransaction – optional bankHost / bankPort", () => {
  const base = { account: "alice", operation: "balance" };

  test("accepts valid bankHost string", () => {
    expect(validateTransaction({ ...base, bankHost: "127.0.0.1" })).toBeNull();
  });

  test("rejects empty bankHost", () => {
    expect(validateTransaction({ ...base, bankHost: "" })).not.toBeNull();
  });

  test("rejects bankHost longer than 15 chars", () => {
    expect(
      validateTransaction({ ...base, bankHost: "1234.1234.1234.1" }),
    ).not.toBeNull();
  });

  test("accepts valid port 3000", () => {
    expect(validateTransaction({ ...base, bankPort: 3000 })).toBeNull();
  });

  test("rejects port below 1024", () => {
    expect(validateTransaction({ ...base, bankPort: 1023 })).not.toBeNull();
  });

  test("rejects port above 65535", () => {
    expect(validateTransaction({ ...base, bankPort: 65536 })).not.toBeNull();
  });

  test("rejects non-integer port", () => {
    expect(validateTransaction({ ...base, bankPort: 30.5 })).not.toBeNull();
  });
});

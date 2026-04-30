#!/bin/bash
# Integration tests for bank/atm system
# Usage: ./test_integration.sh [port]

set -e  # Exit on first error

PORT=${1:-4001}
AUTH_FILE="test_integration.auth"
BANK_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    if [ -n "$BANK_PID" ] && kill -0 "$BANK_PID" 2>/dev/null; then
        kill -TERM "$BANK_PID" 2>/dev/null || true
        wait "$BANK_PID" 2>/dev/null || true
    fi
    rm -f "$AUTH_FILE" *.card 2>/dev/null || true
}

trap cleanup EXIT

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test function
run_test() {
    local name="$1"
    local expected_exit="$2"
    local expected_output="$3"
    shift 3
    local cmd=("$@")
    
    TESTS_RUN=$((TESTS_RUN + 1))
    printf "Testing: %-40s ... " "$name"
    
    set +e
    output=$("${cmd[@]}" 2>&1)
    actual_exit=$?
    set -e
    
    if [ "$actual_exit" -ne "$expected_exit" ]; then
        echo -e "${RED}FAIL${NC} (exit=$actual_exit, expected=$expected_exit)"
        echo "  Output: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
    
    if [ -n "$expected_output" ] && ! echo "$output" | grep -q "$expected_output"; then
        echo -e "${RED}FAIL${NC} (output mismatch)"
        echo "  Expected: $expected_output"
        echo "  Got: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
    
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    return 0
}

echo "=========================================="
echo "  Secure ATM Integration Tests"
echo "=========================================="
echo ""

# Check executables exist
if [ ! -x "./bank" ] || [ ! -x "./atm" ]; then
    echo -e "${RED}ERROR: bank and/or atm executables not found${NC}"
    echo "Run 'make' first to build the project"
    exit 1
fi

# Clean up any previous test files
rm -f "$AUTH_FILE" *.card 2>/dev/null || true

echo -e "${YELLOW}Starting bank server on port $PORT...${NC}"
./bank -p "$PORT" -s "$AUTH_FILE" &
BANK_PID=$!
sleep 1

# Verify bank started
if ! kill -0 "$BANK_PID" 2>/dev/null; then
    echo -e "${RED}ERROR: Bank failed to start${NC}"
    exit 1
fi

# Verify auth file created
if [ ! -f "$AUTH_FILE" ]; then
    echo -e "${RED}ERROR: Auth file not created${NC}"
    exit 1
fi

echo -e "${GREEN}Bank started (PID: $BANK_PID)${NC}"
echo ""

# ============================================================================
# Basic functionality tests
# ============================================================================
echo "=== Basic Functionality ==="

run_test "Create account (alice, 1000.00)" 0 '"account":"alice"' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -n 1000.00

run_test "Check balance (alice = 1000)" 0 '"balance":1000' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -g

run_test "Deposit 500.00 to alice" 0 '"deposit":500' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -d 500.00

run_test "Check balance (alice = 1500)" 0 '"balance":1500' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -g

run_test "Withdraw 250.50 from alice" 0 '"withdraw":250.5' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -w 250.50

run_test "Check balance (alice = 1249.50)" 0 '"balance":1249.5' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -g

# ============================================================================
# Multiple accounts test
# ============================================================================
echo ""
echo "=== Multiple Accounts ==="

run_test "Create account (bob, 500.00)" 0 '"account":"bob"' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a bob -n 500.00

run_test "Create account (charlie, 100.00)" 0 '"account":"charlie"' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a charlie -n 100.00

run_test "Check balance (bob = 500)" 0 '"balance":500' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a bob -g

run_test "Check balance (charlie = 100)" 0 '"balance":100' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a charlie -g

# ============================================================================
# Error handling tests
# ============================================================================
echo ""
echo "=== Error Handling ==="

run_test "Duplicate account creation" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -n 100.00

# Insufficient funds: bank sends a "fail" response → ATM returns 255 (OTHER_ERROR).
# Balance must NOT change because the bank never applied the withdrawal.
run_test "Insufficient funds" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a charlie -w 200.00

run_test "Charlie balance unchanged after insufficient funds" 0 '"balance":100' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a charlie -g

run_test "Non-existent account" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a nonexistent -g

# Wrong card: bank sends a {"status":"fail"} response (HMAC mismatch is a
# business-logic rejection, not a protocol drop) → ATM parses the response,
# sees status != "success", and exits 255 (OTHER_ERROR).
cp alice.card wrong.card
run_test "Wrong card file (exit 255)" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a bob -c wrong.card -g
rm -f wrong.card

run_test "Bob balance unchanged after wrong card access" 0 '"balance":500' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a bob -g

# ============================================================================
# Input validation tests
# ============================================================================
echo ""
echo "=== Input Validation ==="

run_test "Invalid account (uppercase)" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a Alice -n 100.00

run_test "Invalid account (space)" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a "alice bob" -n 100.00

run_test "Invalid amount (no decimals)" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -d 100

run_test "Invalid amount (leading zero)" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -d 01.00

run_test "Invalid amount (negative)" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -d -100.00

run_test "Zero deposit" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -d 0.00

run_test "Below minimum (0.00)" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -w 0.00

# ============================================================================
# Edge cases
# ============================================================================
echo ""
echo "=== Edge Cases ==="

run_test "Minimum deposit (0.01)" 0 '"deposit":0.01' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -d 0.01

run_test "Create with minimum balance" 0 '"initial_balance":10' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a minimum -n 10.00

# ============================================================================
# Rollback & State Integrity
# Verifies the deferred-mutation fix: the bank only commits state changes
# AFTER a response frame is successfully sent.  If the send fails (protocol
# error / connection drop) the ledger must remain unchanged.
# ============================================================================
echo ""
echo "=== Rollback & State Integrity ==="

# -- 1. Auth-failure rollback ------------------------------------------------
# Use bob's card against alice's account.  Bank sends {"status":"fail"} (HMAC
# mismatch is a business-logic rejection) → ATM exits 255 (OTHER_ERROR).
# No balance mutation is staged for wrong-card requests, so alice's ledger
# entry is never touched.
cp bob.card alice_wrong.card

run_test "Wrong-card deposit attempt (exit 255)" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -c alice_wrong.card -d 50.00

run_test "Alice balance unchanged after wrong-card deposit" 0 '"balance":1249.51' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -g

run_test "Wrong-card withdrawal attempt (exit 255)" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -c alice_wrong.card -w 50.00

run_test "Alice balance unchanged after wrong-card withdrawal" 0 '"balance":1249.51' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -g

rm -f alice_wrong.card

# -- 2. MITM TCP-RST rollback ------------------------------------------------
# The MITM proxy forwards a valid deposit request to the bank, then force-
# resets the bank socket before the bank can send its response.
# Expected behaviour (with the deferred-mutation fix):
#   - bank's session.send() fails  → handle_client() returns early, no commit
#   - bank prints "protocol_error"
#   - ATM's session.recv() fails   → exits 63
#   - alice's balance stays at 1249.51 (deposit of 50.00 was NOT applied)
if command -v python3 >/dev/null 2>&1; then
    MITM_PORT=$((PORT + 1))
    python3 ./scripts/mitm_proxy.py "$MITM_PORT" "$PORT" >/dev/null 2>&1 &
    MITM_PID=$!
    sleep 0.4   # give the proxy time to bind and listen

    set +e
    ./atm -p "$MITM_PORT" -s "$AUTH_FILE" -a alice -d 50.00 >/dev/null 2>&1
    MITM_ATM_EXIT=$?
    set -e
    wait "$MITM_PID" 2>/dev/null || true

    TESTS_RUN=$((TESTS_RUN + 1))
    printf "Testing: %-40s ... " "MITM deposit: ATM exits 63 (no response)"
    if [ "$MITM_ATM_EXIT" -eq 63 ]; then
        echo -e "${GREEN}PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}FAIL${NC} (exit=$MITM_ATM_EXIT, expected=63)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    run_test "Alice balance unchanged after MITM-dropped deposit" 0 '"balance":1249.51' \
        ./atm -p "$PORT" -s "$AUTH_FILE" -a alice -g
else
    echo -e "${YELLOW}  Skipping MITM rollback test (python3 not available)${NC}"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=========================================="
echo "  Test Results"
echo "=========================================="
echo -e "  Total:  $TESTS_RUN"
echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
    exit 1
else
    echo -e "  ${GREEN}All tests passed!${NC}"
    exit 0
fi

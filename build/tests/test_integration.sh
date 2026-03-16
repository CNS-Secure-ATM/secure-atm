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

run_test "Insufficient funds" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a charlie -w 200.00

run_test "Non-existent account" 255 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a nonexistent -g

# Wrong card test
cp alice.card wrong.card
run_test "Wrong card file" 63 '' \
    ./atm -p "$PORT" -s "$AUTH_FILE" -a bob -c wrong.card -g
rm -f wrong.card

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

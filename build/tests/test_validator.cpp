// Validator unit tests
#include "test_framework.hpp"
#include "validator/validator.hpp"
#include <string>

// ============================================================================
// Account validation tests
// ============================================================================

TEST(account_valid_basic) {
    EXPECT_TRUE(validator::is_valid_account("bob"));
    EXPECT_TRUE(validator::is_valid_account("alice123"));
    EXPECT_TRUE(validator::is_valid_account("user_name"));
    EXPECT_TRUE(validator::is_valid_account("user-name"));
    EXPECT_TRUE(validator::is_valid_account("user.name"));
    EXPECT_TRUE(validator::is_valid_account("a"));
    return true;
}

TEST(account_valid_numbers) {
    EXPECT_TRUE(validator::is_valid_account("123"));
    EXPECT_TRUE(validator::is_valid_account("0"));
    EXPECT_TRUE(validator::is_valid_account("a1b2c3"));
    return true;
}

TEST(account_valid_special_chars) {
    EXPECT_TRUE(validator::is_valid_account("_"));
    EXPECT_TRUE(validator::is_valid_account("."));
    EXPECT_TRUE(validator::is_valid_account(".."));
    EXPECT_TRUE(validator::is_valid_account("_._"));
    EXPECT_TRUE(validator::is_valid_account("---"));
    return true;
}

TEST(account_invalid_empty) {
    EXPECT_FALSE(validator::is_valid_account(""));
    return true;
}

TEST(account_invalid_uppercase) {
    EXPECT_FALSE(validator::is_valid_account("Bob"));
    EXPECT_FALSE(validator::is_valid_account("ALICE"));
    EXPECT_FALSE(validator::is_valid_account("userA"));
    return true;
}

TEST(account_invalid_special) {
    EXPECT_FALSE(validator::is_valid_account("user@name"));
    EXPECT_FALSE(validator::is_valid_account("user name"));
    EXPECT_FALSE(validator::is_valid_account("user/name"));
    EXPECT_FALSE(validator::is_valid_account("user\\name"));
    EXPECT_FALSE(validator::is_valid_account("user$name"));
    return true;
}

TEST(account_invalid_too_long) {
    std::string long_account(123, 'a');  // 123 chars, max is 122
    EXPECT_FALSE(validator::is_valid_account(long_account));
    
    std::string max_account(122, 'a');
    EXPECT_TRUE(validator::is_valid_account(max_account));
    return true;
}

// ============================================================================
// Filename validation tests
// ============================================================================

TEST(filename_valid_basic) {
    EXPECT_TRUE(validator::is_valid_filename("bank.auth"));
    EXPECT_TRUE(validator::is_valid_filename("bob.card"));
    EXPECT_TRUE(validator::is_valid_filename("file123"));
    EXPECT_TRUE(validator::is_valid_filename("a"));
    return true;
}

TEST(filename_invalid_dot) {
    EXPECT_FALSE(validator::is_valid_filename("."));
    EXPECT_FALSE(validator::is_valid_filename(".."));
    return true;
}

TEST(filename_invalid_empty) {
    EXPECT_FALSE(validator::is_valid_filename(""));
    return true;
}

TEST(filename_invalid_too_long) {
    std::string long_name(128, 'a');  // 128 chars, max is 127
    EXPECT_FALSE(validator::is_valid_filename(long_name));
    
    std::string max_name(127, 'a');
    EXPECT_TRUE(validator::is_valid_filename(max_name));
    return true;
}

TEST(filename_invalid_special) {
    EXPECT_FALSE(validator::is_valid_filename("file/name"));
    EXPECT_FALSE(validator::is_valid_filename("file:name"));
    EXPECT_FALSE(validator::is_valid_filename("file name"));
    return true;
}

// ============================================================================
// Amount validation tests
// ============================================================================

TEST(amount_valid_basic) {
    EXPECT_TRUE(validator::is_valid_amount("0.00"));
    EXPECT_TRUE(validator::is_valid_amount("1.00"));
    EXPECT_TRUE(validator::is_valid_amount("10.00"));
    EXPECT_TRUE(validator::is_valid_amount("100.50"));
    EXPECT_TRUE(validator::is_valid_amount("999.99"));
    return true;
}

TEST(amount_valid_large) {
    EXPECT_TRUE(validator::is_valid_amount("1000000.00"));
    EXPECT_TRUE(validator::is_valid_amount("4294967295.99"));  // max
    return true;
}

TEST(amount_valid_decimals) {
    EXPECT_TRUE(validator::is_valid_amount("0.01"));
    EXPECT_TRUE(validator::is_valid_amount("0.10"));
    EXPECT_TRUE(validator::is_valid_amount("123.45"));
    return true;
}

TEST(amount_invalid_format) {
    EXPECT_FALSE(validator::is_valid_amount(""));
    EXPECT_FALSE(validator::is_valid_amount("100"));      // no decimals
    EXPECT_FALSE(validator::is_valid_amount("100."));     // no decimal digits
    EXPECT_FALSE(validator::is_valid_amount("100.0"));    // only 1 decimal
    EXPECT_FALSE(validator::is_valid_amount("100.000"));  // 3 decimals
    EXPECT_FALSE(validator::is_valid_amount(".00"));      // no integer part
    return true;
}

TEST(amount_invalid_leading_zero) {
    EXPECT_FALSE(validator::is_valid_amount("00.00"));
    EXPECT_FALSE(validator::is_valid_amount("01.00"));
    EXPECT_FALSE(validator::is_valid_amount("007.00"));
    return true;
}

TEST(amount_invalid_negative) {
    EXPECT_FALSE(validator::is_valid_amount("-1.00"));
    EXPECT_FALSE(validator::is_valid_amount("-100.00"));
    return true;
}

TEST(amount_invalid_too_large) {
    EXPECT_FALSE(validator::is_valid_amount("4294967296.00"));  // overflow
    EXPECT_FALSE(validator::is_valid_amount("99999999999.00"));
    return true;
}

TEST(amount_invalid_non_numeric) {
    EXPECT_FALSE(validator::is_valid_amount("abc.de"));
    EXPECT_FALSE(validator::is_valid_amount("100.ab"));
    EXPECT_FALSE(validator::is_valid_amount("1O0.00"));  // letter O
    return true;
}

// ============================================================================
// Port validation tests
// ============================================================================

TEST(port_valid_range) {
    EXPECT_TRUE(validator::is_valid_port(1024));
    EXPECT_TRUE(validator::is_valid_port(3000));
    EXPECT_TRUE(validator::is_valid_port(8080));
    EXPECT_TRUE(validator::is_valid_port(65535));
    return true;
}

TEST(port_invalid_low) {
    EXPECT_FALSE(validator::is_valid_port(0));
    EXPECT_FALSE(validator::is_valid_port(1));
    EXPECT_FALSE(validator::is_valid_port(80));
    EXPECT_FALSE(validator::is_valid_port(443));
    EXPECT_FALSE(validator::is_valid_port(1023));
    return true;
}

TEST(port_invalid_high) {
    EXPECT_FALSE(validator::is_valid_port(65536));
    EXPECT_FALSE(validator::is_valid_port(100000));
    return true;
}

// ============================================================================
// IPv4 validation tests
// ============================================================================

TEST(ipv4_valid_basic) {
    EXPECT_TRUE(validator::is_valid_ipv4("127.0.0.1"));
    EXPECT_TRUE(validator::is_valid_ipv4("192.168.1.1"));
    EXPECT_TRUE(validator::is_valid_ipv4("10.0.0.1"));
    EXPECT_TRUE(validator::is_valid_ipv4("255.255.255.255"));
    EXPECT_TRUE(validator::is_valid_ipv4("0.0.0.0"));
    return true;
}

TEST(ipv4_invalid_format) {
    EXPECT_FALSE(validator::is_valid_ipv4(""));
    EXPECT_FALSE(validator::is_valid_ipv4("localhost"));
    EXPECT_FALSE(validator::is_valid_ipv4("192.168.1"));
    EXPECT_FALSE(validator::is_valid_ipv4("192.168.1.1.1"));
    return true;
}

TEST(ipv4_invalid_range) {
    EXPECT_FALSE(validator::is_valid_ipv4("256.0.0.1"));
    EXPECT_FALSE(validator::is_valid_ipv4("192.168.1.256"));
    return true;
}

// ============================================================================
// Amount parsing tests
// ============================================================================

TEST(parse_amount_valid) {
    auto cents = validator::parse_amount_to_cents("100.00");
    EXPECT_TRUE(cents.has_value());
    EXPECT_EQ(*cents, 10000UL);
    
    cents = validator::parse_amount_to_cents("0.01");
    EXPECT_TRUE(cents.has_value());
    EXPECT_EQ(*cents, 1UL);
    
    cents = validator::parse_amount_to_cents("123.45");
    EXPECT_TRUE(cents.has_value());
    EXPECT_EQ(*cents, 12345UL);
    return true;
}

TEST(parse_amount_invalid) {
    EXPECT_FALSE(validator::parse_amount_to_cents("invalid").has_value());
    EXPECT_FALSE(validator::parse_amount_to_cents("").has_value());
    EXPECT_FALSE(validator::parse_amount_to_cents("-1.00").has_value());
    return true;
}

TEST(format_cents) {
    EXPECT_EQ(validator::format_cents_to_amount(0), "0.00");
    EXPECT_EQ(validator::format_cents_to_amount(1), "0.01");
    EXPECT_EQ(validator::format_cents_to_amount(10), "0.10");
    EXPECT_EQ(validator::format_cents_to_amount(100), "1.00");
    EXPECT_EQ(validator::format_cents_to_amount(12345), "123.45");
    return true;
}

int main() {
    return test::run_tests();
}

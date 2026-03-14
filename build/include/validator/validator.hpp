#ifndef VALIDATOR_VALIDATOR_HPP
#define VALIDATOR_VALIDATOR_HPP

#include <string>
#include <cstdint>
#include <optional>

namespace validator 
{

// Account name: [_\-\.0-9a-z]{1,122}, allows "." and ".."
bool is_valid_account(const std::string& account);

// File name: [_\-\.0-9a-z]{1,127}, NOT "." or ".."
bool is_valid_filename(const std::string& filename);

// Amount: (0|[1-9][0-9]*)\.[0-9]{2}, range 0.00 to 4294967295.99
bool is_valid_amount(const std::string& amount);

// Port: 1024-65535
bool is_valid_port(const std::string& port);
bool is_valid_port(int port);

// IPv4: dotted decimal (e.g., 192.168.1.1)
bool is_valid_ipv4(const std::string& ip);

// Parse amount string to cents (uint64_t)
// Returns empty on invalid input
std::optional<uint64_t> parse_amount_to_cents(const std::string& amount);

// Format cents to amount string (e.g., 12345 -> "123.45")
std::string format_cents_to_amount(uint64_t cents);

// Parse port string to int
std::optional<int> parse_port(const std::string& port);

// Check if a character is valid for file/account names
bool is_valid_name_char(char c);

} // namespace validator

#endif // VALIDATOR_VALIDATOR_HPP

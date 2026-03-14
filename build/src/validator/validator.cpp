#include "validator/validator.hpp"
#include <regex>
#include <sstream>
#include <iomanip>
#include <cstdlib>

namespace validator {

bool is_valid_name_char(char c) {
    return (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '_' || c == '-' || c == '.';
}

bool is_valid_account(const std::string& account) {
    // Account: 1-122 chars, [_\-\.0-9a-z]
    if (account.empty() || account.size() > 122) {
        return false;
    }
    for (char c : account) {
        if (!is_valid_name_char(c)) {
            return false;
        }
    }
    return true;
}

bool is_valid_filename(const std::string& filename) {
    // Filename: 1-127 chars, [_\-\.0-9a-z], not "." or ".."
    if (filename.empty() || filename.size() > 127) {
        return false;
    }
    if (filename == "." || filename == "..") {
        return false;
    }
    for (char c : filename) {
        if (!is_valid_name_char(c)) {
            return false;
        }
    }
    return true;
}

bool is_valid_amount(const std::string& amount) {
    // Format: (0|[1-9][0-9]*)\.[0-9]{2}
    // Range: 0.00 to 4294967295.99
    
    if (amount.size() < 4) {  // Minimum: "0.00"
        return false;
    }
    
    // Find decimal point
    size_t dot_pos = amount.find('.');
    if (dot_pos == std::string::npos || dot_pos == 0) {
        return false;
    }
    
    // Check fractional part (exactly 2 digits)
    if (amount.size() - dot_pos != 3) {
        return false;
    }
    if (!std::isdigit(amount[dot_pos + 1]) || !std::isdigit(amount[dot_pos + 2])) {
        return false;
    }
    
    // Check integer part
    std::string int_part = amount.substr(0, dot_pos);
    if (int_part.empty()) {
        return false;
    }
    
    // No leading zeros unless the number is just "0"
    if (int_part.size() > 1 && int_part[0] == '0') {
        return false;
    }
    
    // All digits
    for (char c : int_part) {
        if (!std::isdigit(c)) {
            return false;
        }
    }
    
    // Check range (integer part max is 4294967295)
    if (int_part.size() > 10) {
        return false;
    }
    if (int_part.size() == 10) {
        if (int_part > "4294967295") {
            return false;
        }
    }
    
    return true;
}

bool is_valid_port(int port) {
    return port >= 1024 && port <= 65535;
}

bool is_valid_port(const std::string& port) {
    auto parsed = parse_port(port);
    return parsed.has_value() && is_valid_port(*parsed);
}

bool is_valid_ipv4(const std::string& ip) {
    // IPv4: four octets (0-255) separated by dots
    if (ip.empty() || ip.size() > 15) {
        return false;
    }
    
    int octets[4];
    int count = 0;
    size_t pos = 0;
    
    for (int i = 0; i < 4; i++) {
        if (pos >= ip.size()) {
            return false;
        }
        
        // Find next dot or end
        size_t dot = ip.find('.', pos);
        if (i < 3 && dot == std::string::npos) {
            return false;
        }
        if (i == 3 && dot != std::string::npos) {
            return false;
        }
        
        size_t end = (i < 3) ? dot : ip.size();
        std::string octet_str = ip.substr(pos, end - pos);
        
        // Empty octet
        if (octet_str.empty()) {
            return false;
        }
        
        // Leading zeros not allowed (except "0" itself)
        if (octet_str.size() > 1 && octet_str[0] == '0') {
            return false;
        }
        
        // All digits
        for (char c : octet_str) {
            if (!std::isdigit(c)) {
                return false;
            }
        }
        
        // Range 0-255
        int val = std::stoi(octet_str);
        if (val < 0 || val > 255) {
            return false;
        }
        
        octets[count++] = val;
        pos = end + 1;
    }
    
    return count == 4;
}

std::optional<uint64_t> parse_amount_to_cents(const std::string& amount) {
    if (!is_valid_amount(amount)) {
        return std::nullopt;
    }
    
    size_t dot_pos = amount.find('.');
    std::string int_part = amount.substr(0, dot_pos);
    std::string frac_part = amount.substr(dot_pos + 1);
    
    // Convert to cents
    uint64_t dollars = 0;
    if (!int_part.empty()) {
        dollars = std::stoull(int_part);
    }
    uint64_t cents = std::stoull(frac_part);
    
    // Check for overflow
    if (dollars > 42949672959ULL) {  // Max cents / 100
        return std::nullopt;
    }
    
    return dollars * 100 + cents;
}

std::string format_cents_to_amount(uint64_t cents) {
    uint64_t dollars = cents / 100;
    uint64_t frac = cents % 100;
    
    std::ostringstream oss;
    oss << dollars << "." << std::setw(2) << std::setfill('0') << frac;
    return oss.str();
}

std::optional<int> parse_port(const std::string& port) {
    if (port.empty()) {
        return std::nullopt;
    }
    
    // No leading zeros (except "0" itself, but 0 is invalid port)
    if (port.size() > 1 && port[0] == '0') {
        return std::nullopt;
    }
    
    // All digits
    for (char c : port) {
        if (!std::isdigit(c)) {
            return std::nullopt;
        }
    }
    
    // Reasonable length
    if (port.size() > 5) {
        return std::nullopt;
    }
    
    try {
        int val = std::stoi(port);
        if (val < 0 || val > 65535) {
            return std::nullopt;
        }
        return val;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace validator

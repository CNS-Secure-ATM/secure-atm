// ATM Client
// Usage: atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -n/-d/-w/-g

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common/types.hpp"
#include "common/exitcodes.hpp"
#include "crypto/keys.hpp"
#include "crypto/hmac.hpp"
#include "protocol/session.hpp"
#include "protocol/framing.hpp"
#include "validator/validator.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

enum class Mode {
    NONE,
    CREATE,    // -n
    DEPOSIT,   // -d
    WITHDRAW,  // -w
    BALANCE    // -g
};

struct Options {
    std::string auth_file = "bank.auth";
    std::string ip_address = "127.0.0.1";
    int port = 3000;
    std::string card_file;  // Default: <account>.card
    std::string card_content; // Optional: direct card content (hex)
    std::string account;
    Mode mode = Mode::NONE;
    std::string amount;  // For -n, -d, -w
    bool print_card_stdout = false; // Optional: print new card content instead of writing file
};

// Print JSON result
void print_json_result(const json& j) {
    std::cout << j.dump() << std::endl;
    std::cout.flush();
}

void print_usage(const char* prog_name) {
    std::cout << "Usage:\n";
    std::cout << "  " << prog_name << " [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -n <amount> [-m]\n";
    std::cout << "  " << prog_name << " [-s <auth-file>] [-i <ip-address>] [-p <port>] (-c <card-file> | -C <card-content-hex>) -a <account> -d <amount>\n";
    std::cout << "  " << prog_name << " [-s <auth-file>] [-i <ip-address>] [-p <port>] (-c <card-file> | -C <card-content-hex>) -a <account> -w <amount>\n";
    std::cout << "  " << prog_name << " [-s <auth-file>] [-i <ip-address>] [-p <port>] (-c <card-file> | -C <card-content-hex>) -a <account> -g\n";
    std::cout << "  " << prog_name << " -h | --help\n\n";
    std::cout << "Options:\n";
    std::cout << "  -s <auth-file>  Bank auth file (default: bank.auth)\n";
    std::cout << "  -i <ip-address> Bank IPv4 address (default: 127.0.0.1)\n";
    std::cout << "  -p <port>       Bank port (default: 3000)\n";
    std::cout << "  -c <card-file>  Card file (default: <account>.card)\n";
    std::cout << "  -C <content>    Card content (64 hex chars), use instead of -c\n";
    std::cout << "  -a <account>    Account name (required)\n";
    std::cout << "  -n <amount>     Create account with initial balance (>= 10.00)\n";
    std::cout << "  -m              Create mode only: print new card content to stdout JSON and do not write card file\n";
    std::cout << "  -d <amount>     Deposit amount (> 0.00)\n";
    std::cout << "  -w <amount>     Withdraw amount (> 0.00)\n";
    std::cout << "  -g              Get account balance\n";
    std::cout << "  -h, --help      Show this help message\n";
    std::cout.flush();
}

// Read auth file and derive keys
bool read_auth_file(const std::string& filename, crypto::DerivedKeys& keys) {
    std::ifstream in(filename);
    if (!in.good()) {
        return false;
    }
    
    std::string hex;
    std::getline(in, hex);
    in.close();
    
    // Remove any whitespace
    hex.erase(std::remove_if(hex.begin(), hex.end(), ::isspace), hex.end());
    
    if (hex.size() != secure::KEY_SIZE * 2) {
        return false;
    }
    
    auto master = secure::SecureBuffer::from_hex(hex);
    if (master.empty() || master.size() != secure::KEY_SIZE) {
        return false;
    }
    
    keys = crypto::derive_keys(master);
    return keys.valid();
}

// Read card file
bool read_card_file(const std::string& filename, secure::SecureBuffer& card_secret) {
    std::ifstream in(filename);
    if (!in.good()) {
        return false;
    }
    
    std::string hex;
    std::getline(in, hex);
    in.close();
    
    hex.erase(std::remove_if(hex.begin(), hex.end(), ::isspace), hex.end());
    
    if (hex.size() != secure::KEY_SIZE * 2) {
        return false;
    }
    
    card_secret = secure::SecureBuffer::from_hex(hex);
    return card_secret.size() == secure::KEY_SIZE;
}

// Write card file
bool write_card_file(const std::string& filename, const secure::SecureBuffer& card_secret) {
    // Check file doesn't exist
    {
        std::ifstream check(filename);
        if (check.good()) {
            return false;
        }
    }
    
    std::ofstream out(filename);
    if (!out.good()) {
        return false;
    }
    
    out << card_secret.to_hex();
    out.close();
    return out.good();
}

// Connect to bank server
int connect_to_bank(const std::string& ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        print_usage(argv[0]);
        return exitcode::OTHER_ERROR;
    }

    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--help") {
            print_usage(argv[0]);
            return exitcode::SUCCESS;
        }
    }

    Options opts;
    std::string created_card_hex;
    
    // Track seen flags
    bool seen_s = false, seen_i = false, seen_p = false;
    bool seen_c = false, seen_C = false, seen_a = false, seen_m = false;
    bool seen_n = false, seen_d = false, seen_w = false, seen_g = false;
    
    int opt;
    while ((opt = getopt(argc, argv, "hs:i:p:c:C:a:n:d:w:gm")) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return exitcode::SUCCESS;
            case 's':
                if (seen_s) return exitcode::OTHER_ERROR;
                seen_s = true;
                opts.auth_file = optarg;
                if (!validator::is_valid_filename(opts.auth_file)) {
                    return exitcode::OTHER_ERROR;
                }
                break;
            case 'i':
                if (seen_i) return exitcode::OTHER_ERROR;
                seen_i = true;
                opts.ip_address = optarg;
                if (!validator::is_valid_ipv4(opts.ip_address)) {
                    return exitcode::OTHER_ERROR;
                }
                break;
            case 'p':
                if (seen_p) return exitcode::OTHER_ERROR;
                seen_p = true;
                {
                    auto parsed = validator::parse_port(optarg);
                    if (!parsed || !validator::is_valid_port(*parsed)) {
                        return exitcode::OTHER_ERROR;
                    }
                    opts.port = *parsed;
                }
                break;
            case 'c':
                if (seen_c) return exitcode::OTHER_ERROR;
                seen_c = true;
                opts.card_file = optarg;
                if (!validator::is_valid_filename(opts.card_file)) {
                    return exitcode::OTHER_ERROR;
                }
                break;
            case 'C':
                if (seen_C) return exitcode::OTHER_ERROR;
                seen_C = true;
                opts.card_content = optarg;
                break;
            case 'a':
                if (seen_a) return exitcode::OTHER_ERROR;
                seen_a = true;
                opts.account = optarg;
                if (!validator::is_valid_account(opts.account)) {
                    return exitcode::OTHER_ERROR;
                }
                break;
            case 'n':
                if (seen_n || seen_d || seen_w || seen_g) return exitcode::OTHER_ERROR;
                seen_n = true;
                opts.mode = Mode::CREATE;
                opts.amount = optarg;
                break;
            case 'd':
                if (seen_n || seen_d || seen_w || seen_g) return exitcode::OTHER_ERROR;
                seen_d = true;
                opts.mode = Mode::DEPOSIT;
                opts.amount = optarg;
                break;
            case 'w':
                if (seen_n || seen_d || seen_w || seen_g) return exitcode::OTHER_ERROR;
                seen_w = true;
                opts.mode = Mode::WITHDRAW;
                opts.amount = optarg;
                break;
            case 'g':
                if (seen_n || seen_d || seen_w || seen_g) return exitcode::OTHER_ERROR;
                seen_g = true;
                opts.mode = Mode::BALANCE;
                break;
            case 'm':
                if (seen_m) return exitcode::OTHER_ERROR;
                seen_m = true;
                opts.print_card_stdout = true;
                break;
            default:
                return exitcode::OTHER_ERROR;
        }
    }
    
    // Check for extra arguments
    if (optind != argc) {
        return exitcode::OTHER_ERROR;
    }
    
    // Required: account and mode
    if (!seen_a || opts.mode == Mode::NONE) {
        return exitcode::OTHER_ERROR;
    }

    // -c and -C are mutually exclusive
    if (seen_c && seen_C) {
        return exitcode::OTHER_ERROR;
    }

    // -m is create-mode only
    if (opts.print_card_stdout && opts.mode != Mode::CREATE) {
        return exitcode::OTHER_ERROR;
    }

    // -C is only meaningful for non-create operations
    if (seen_C && opts.mode == Mode::CREATE) {
        return exitcode::OTHER_ERROR;
    }
    
    // Validate amount for modes that need it
    if (opts.mode == Mode::CREATE || opts.mode == Mode::DEPOSIT || opts.mode == Mode::WITHDRAW) {
        if (!validator::is_valid_amount(opts.amount)) {
            return exitcode::OTHER_ERROR;
        }
        auto cents = validator::parse_amount_to_cents(opts.amount);
        if (!cents) {
            return exitcode::OTHER_ERROR;
        }
        // Create requires >= 10.00
        if (opts.mode == Mode::CREATE && *cents < 1000) {
            return exitcode::OTHER_ERROR;
        }
        // Deposit/withdraw requires > 0
        if ((opts.mode == Mode::DEPOSIT || opts.mode == Mode::WITHDRAW) && *cents == 0) {
            return exitcode::OTHER_ERROR;
        }
    }
    
    // Default card file (if card content was not supplied directly)
    if (opts.card_file.empty() && !seen_C) {
        opts.card_file = opts.account + ".card";
        if (!validator::is_valid_filename(opts.card_file)) {
            return exitcode::OTHER_ERROR;
        }
    }
    
    // Read auth file
    crypto::DerivedKeys keys;
    if (!read_auth_file(opts.auth_file, keys)) {
        return exitcode::OTHER_ERROR;
    }
    
    // For create mode, card file must NOT exist
    // For other modes, card file must exist
    secure::SecureBuffer card_secret;
    if (opts.mode == Mode::CREATE) {
        if (!opts.print_card_stdout) {
            std::ifstream check(opts.card_file);
            if (check.good()) {
                return exitcode::OTHER_ERROR;  // Card file exists
            }
        }
    } else {
        if (seen_C) {
            opts.card_content.erase(std::remove_if(opts.card_content.begin(), opts.card_content.end(), ::isspace), opts.card_content.end());
            if (opts.card_content.size() != secure::KEY_SIZE * 2) {
                return exitcode::OTHER_ERROR;
            }
            card_secret = secure::SecureBuffer::from_hex(opts.card_content);
            if (card_secret.size() != secure::KEY_SIZE) {
                return exitcode::OTHER_ERROR;
            }
        } else {
            if (!read_card_file(opts.card_file, card_secret)) {
                return exitcode::OTHER_ERROR;
            }
        }
    }
    
    // Connect to bank
    int sockfd = connect_to_bank(opts.ip_address, opts.port);
    if (sockfd < 0) {
        return exitcode::PROTOCOL_ERROR;
    }
    
    // Set timeout
    if (!protocol::set_socket_timeout(sockfd, secure::TIMEOUT_SECONDS)) {
        close(sockfd);
        return exitcode::PROTOCOL_ERROR;
    }
    
    // Create session
    protocol::Session session(sockfd, keys);
    if (!session.is_valid()) {
        close(sockfd);
        return exitcode::PROTOCOL_ERROR;
    }
    
    // Receive challenge
    auto challenge_str = session.recv();
    if (!challenge_str) {
        close(sockfd);
        return exitcode::PROTOCOL_ERROR;
    }
    
    json challenge_msg;
    try {
        challenge_msg = json::parse(*challenge_str);
    } catch (...) {
        close(sockfd);
        return exitcode::PROTOCOL_ERROR;
    }
    
    if (!challenge_msg.contains("type") || challenge_msg["type"] != "challenge" ||
        !challenge_msg.contains("challenge")) {
        close(sockfd);
        return exitcode::PROTOCOL_ERROR;
    }
    
    std::string challenge_hex = challenge_msg["challenge"];
    auto challenge = secure::SecureBuffer::from_hex(challenge_hex);
    if (challenge.empty() || challenge.size() != secure::CHALLENGE_SIZE) {
        close(sockfd);
        return exitcode::PROTOCOL_ERROR;
    }
    
    // Build request
    json request;
    request["type"] = "request";
    request["account"] = opts.account;
    
    switch (opts.mode) {
        case Mode::CREATE:
            request["operation"] = "create";
            request["amount"] = opts.amount;
            break;
        case Mode::DEPOSIT:
            request["operation"] = "deposit";
            request["amount"] = opts.amount;
            {
                auto proof = crypto::compute_card_proof(card_secret, challenge);
                request["card_proof"] = proof.to_hex();
            }
            break;
        case Mode::WITHDRAW:
            request["operation"] = "withdraw";
            request["amount"] = opts.amount;
            {
                auto proof = crypto::compute_card_proof(card_secret, challenge);
                request["card_proof"] = proof.to_hex();
            }
            break;
        case Mode::BALANCE:
            request["operation"] = "balance";
            {
                auto proof = crypto::compute_card_proof(card_secret, challenge);
                request["card_proof"] = proof.to_hex();
            }
            break;
        default:
            close(sockfd);
            return exitcode::OTHER_ERROR;
    }
    
    // Send request
    if (!session.send(request.dump())) {
        close(sockfd);
        return exitcode::PROTOCOL_ERROR;
    }
    
    // Receive response
    auto response_str = session.recv();
    if (!response_str) {
        close(sockfd);
        return exitcode::PROTOCOL_ERROR;
    }
    
    json response;
    try {
        response = json::parse(*response_str);
    } catch (...) {
        close(sockfd);
        return exitcode::PROTOCOL_ERROR;
    }
    
    close(sockfd);
    
    // Check response
    if (!response.contains("type") || response["type"] != "response" ||
        !response.contains("status")) {
        return exitcode::PROTOCOL_ERROR;
    }
    
    if (response["status"] != "success") {
        return exitcode::OTHER_ERROR;
    }
    
    // For create mode, create the card file
    if (opts.mode == Mode::CREATE) {
        auto new_card_secret = crypto::compute_card_secret(keys.k_card, opts.account);
        if (!opts.print_card_stdout) {
            if (!write_card_file(opts.card_file, new_card_secret)) {
                return exitcode::OTHER_ERROR;
            }
        } else {
            created_card_hex = new_card_secret.to_hex();
        }
    }
    
    // Print result
    json output;
    output["account"] = opts.account;
    
    switch (opts.mode) {
        case Mode::CREATE:
            if (response.contains("initial_balance")) {
                output["initial_balance"] = response["initial_balance"];
            }
            if (!created_card_hex.empty()) {
                output["card"] = created_card_hex;
            }
            break;
        case Mode::DEPOSIT:
            if (response.contains("deposit")) {
                output["deposit"] = response["deposit"];
            }
            break;
        case Mode::WITHDRAW:
            if (response.contains("withdraw")) {
                output["withdraw"] = response["withdraw"];
            }
            break;
        case Mode::BALANCE:
            if (response.contains("balance")) {
                output["balance"] = response["balance"];
            }
            break;
        default:
            break;
    }
    
    print_json_result(output);
    
    return exitcode::SUCCESS;
}

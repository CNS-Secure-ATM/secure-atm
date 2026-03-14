// Bank Server
// Usage: bank [-p <port>] [-s <auth-file>]

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <mutex>
#include <csignal>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common/types.hpp"
#include "common/exitcodes.hpp"
#include "crypto/keys.hpp"
#include "crypto/hmac.hpp"
#include "crypto/random.hpp"
#include "protocol/session.hpp"
#include "protocol/framing.hpp"
#include "validator/validator.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

// Global state
static volatile sig_atomic_t g_running = 1;
static int g_listen_fd = -1;

// Account ledger (thread-safe)
static std::unordered_map<std::string, uint64_t> g_accounts;
static std::mutex g_accounts_mutex;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
}

// Print protocol error and return
void protocol_error() {
    std::cout << "protocol_error" << std::endl;
    std::cout.flush();
}

// Format JSON number with proper precision (no trailing zeros, but at least one decimal)
void print_json_result(const json& j) {
    std::cout << j.dump() << std::endl;
    std::cout.flush();
}

// Process a single client connection
void handle_client(int client_fd, const crypto::DerivedKeys& keys) {
    // Set timeout
    if (!protocol::set_socket_timeout(client_fd, secure::TIMEOUT_SECONDS)) {
        close(client_fd);
        protocol_error();
        return;
    }
    
    protocol::Session session(client_fd, keys);
    if (!session.is_valid()) {
        close(client_fd);
        protocol_error();
        return;
    }
    
    // Generate and send challenge
    auto challenge = crypto::random_bytes(secure::CHALLENGE_SIZE);
    if (challenge.empty()) {
        close(client_fd);
        protocol_error();
        return;
    }
    session.set_challenge(challenge);
    
    json challenge_msg;
    challenge_msg["type"] = "challenge";
    challenge_msg["challenge"] = challenge.to_hex();
    
    if (!session.send(challenge_msg.dump())) {
        close(client_fd);
        protocol_error();
        return;
    }
    
    // Receive request
    auto request_str = session.recv();
    if (!request_str) {
        close(client_fd);
        protocol_error();
        return;
    }
    
    json request;
    try {
        request = json::parse(*request_str);
    } catch (...) {
        close(client_fd);
        protocol_error();
        return;
    }
    
    // Validate request structure
    if (!request.contains("type") || request["type"] != "request" ||
        !request.contains("operation") || !request.contains("account")) {
        close(client_fd);
        protocol_error();
        return;
    }
    
    std::string operation = request["operation"];
    std::string account = request["account"];
    
    // Validate account name
    if (!validator::is_valid_account(account)) {
        close(client_fd);
        protocol_error();
        return;
    }
    
    bool success = false;
    json response;
    response["type"] = "response";
    response["account"] = account;
    
    // Lock for account operations
    std::lock_guard<std::mutex> lock(g_accounts_mutex);
    
    if (operation == "create") {
        // Create account - no card proof needed
        if (!request.contains("amount")) {
            close(client_fd);
            protocol_error();
            return;
        }
        
        std::string amount_str = request["amount"];
        auto cents = validator::parse_amount_to_cents(amount_str);
        if (!cents || *cents < 1000) {  // Minimum $10.00 = 1000 cents
            close(client_fd);
            protocol_error();
            return;
        }
        
        // Check account doesn't exist
        if (g_accounts.find(account) != g_accounts.end()) {
            // Account exists - send fail
            response["status"] = "fail";
            session.send(response.dump());
            close(client_fd);
            protocol_error();
            return;
        }
        
        // Create account
        g_accounts[account] = *cents;
        response["status"] = "success";
        response["initial_balance"] = static_cast<double>(*cents) / 100.0;
        success = true;
        
    } else if (operation == "deposit" || operation == "withdraw" || operation == "balance") {
        // These require card proof
        if (!request.contains("card_proof")) {
            close(client_fd);
            protocol_error();
            return;
        }
        
        std::string card_proof_hex = request["card_proof"];
        auto card_proof = secure::SecureBuffer::from_hex(card_proof_hex);
        if (card_proof.empty() || card_proof.size() != secure::HMAC_SIZE) {
            close(client_fd);
            protocol_error();
            return;
        }
        
        // Compute expected card proof
        auto expected_secret = crypto::compute_card_secret(keys.k_card, account);
        auto expected_proof = crypto::compute_card_proof(expected_secret, session.get_challenge());
        
        // Verify card proof (constant time)
        if (!crypto::hmac_verify(expected_proof, card_proof)) {
            close(client_fd);
            protocol_error();
            return;
        }
        
        // Check account exists
        auto it = g_accounts.find(account);
        if (it == g_accounts.end()) {
            response["status"] = "fail";
            session.send(response.dump());
            close(client_fd);
            protocol_error();
            return;
        }
        
        if (operation == "deposit") {
            if (!request.contains("amount")) {
                close(client_fd);
                protocol_error();
                return;
            }
            
            std::string amount_str = request["amount"];
            auto cents = validator::parse_amount_to_cents(amount_str);
            if (!cents || *cents == 0) {
                close(client_fd);
                protocol_error();
                return;
            }
            
            // Check for overflow
            if (it->second > UINT64_MAX - *cents) {
                response["status"] = "fail";
                session.send(response.dump());
                close(client_fd);
                protocol_error();
                return;
            }
            
            it->second += *cents;
            response["status"] = "success";
            response["deposit"] = static_cast<double>(*cents) / 100.0;
            success = true;
            
        } else if (operation == "withdraw") {
            if (!request.contains("amount")) {
                close(client_fd);
                protocol_error();
                return;
            }
            
            std::string amount_str = request["amount"];
            auto cents = validator::parse_amount_to_cents(amount_str);
            if (!cents || *cents == 0) {
                close(client_fd);
                protocol_error();
                return;
            }
            
            // Check sufficient funds
            if (it->second < *cents) {
                response["status"] = "fail";
                session.send(response.dump());
                close(client_fd);
                protocol_error();
                return;
            }
            
            it->second -= *cents;
            response["status"] = "success";
            response["withdraw"] = static_cast<double>(*cents) / 100.0;
            success = true;
            
        } else if (operation == "balance") {
            response["status"] = "success";
            response["balance"] = static_cast<double>(it->second) / 100.0;
            success = true;
        }
    } else {
        close(client_fd);
        protocol_error();
        return;
    }
    
    // Send response
    if (!session.send(response.dump())) {
        close(client_fd);
        protocol_error();
        return;
    }
    
    close(client_fd);
    
    // Print result on success
    if (success) {
        json output;
        output["account"] = account;
        if (operation == "create") {
            output["initial_balance"] = response["initial_balance"];
        } else if (operation == "deposit") {
            output["deposit"] = response["deposit"];
        } else if (operation == "withdraw") {
            output["withdraw"] = response["withdraw"];
        } else if (operation == "balance") {
            output["balance"] = response["balance"];
        }
        print_json_result(output);
    }
}

int main(int argc, char* argv[]) {
    // Default values
    int port = 3000;
    std::string auth_file = "bank.auth";
    
    // Parse arguments
    bool seen_p = false, seen_s = false;
    
    int opt;
    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
            case 'p':
                if (seen_p) return exitcode::OTHER_ERROR;
                seen_p = true;
                {
                    auto parsed = validator::parse_port(optarg);
                    if (!parsed || !validator::is_valid_port(*parsed)) {
                        return exitcode::OTHER_ERROR;
                    }
                    port = *parsed;
                }
                break;
            case 's':
                if (seen_s) return exitcode::OTHER_ERROR;
                seen_s = true;
                auth_file = optarg;
                if (!validator::is_valid_filename(auth_file)) {
                    return exitcode::OTHER_ERROR;
                }
                break;
            default:
                return exitcode::OTHER_ERROR;
        }
    }
    
    // Check for extra arguments
    if (optind != argc) {
        return exitcode::OTHER_ERROR;
    }
    
    // Check auth file doesn't exist
    {
        std::ifstream check(auth_file);
        if (check.good()) {
            return exitcode::OTHER_ERROR;
        }
    }
    
    // Generate master key
    auto master_key = crypto::generate_master_key();
    if (master_key.empty()) {
        return exitcode::OTHER_ERROR;
    }
    
    // Write auth file
    {
        std::ofstream out(auth_file);
        if (!out.good()) {
            return exitcode::OTHER_ERROR;
        }
        out << master_key.to_hex();
        out.close();
        if (!out.good()) {
            std::remove(auth_file.c_str());
            return exitcode::OTHER_ERROR;
        }
    }
    
    // Print created
    std::cout << "created" << std::endl;
    std::cout.flush();
    
    // Derive keys
    auto keys = crypto::derive_keys(master_key);
    if (!keys.valid()) {
        std::remove(auth_file.c_str());
        return exitcode::OTHER_ERROR;
    }
    
    // Set up signal handler
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, nullptr);
    
    // Create socket
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        return exitcode::OTHER_ERROR;
    }
    
    // Set SO_REUSEADDR
    int opt_val = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
    
    // Bind
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    
    if (bind(g_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(g_listen_fd);
        return exitcode::OTHER_ERROR;
    }
    
    // Listen
    if (listen(g_listen_fd, 5) < 0) {
        close(g_listen_fd);
        return exitcode::OTHER_ERROR;
    }
    
    // Accept loop
    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(g_listen_fd, 
            reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
        
        if (client_fd < 0) {
            if (!g_running) break;  // SIGTERM received
            continue;  // Accept error, continue
        }
        
        handle_client(client_fd, keys);
    }
    
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
    }
    
    return exitcode::SUCCESS;
}

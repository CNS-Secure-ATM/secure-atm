#ifndef PROTOCOL_SESSION_HPP
#define PROTOCOL_SESSION_HPP

#include "common/types.hpp"
#include "crypto/keys.hpp"
#include <optional>
#include <string>
#include <cstdint>

namespace protocol {

// Encrypted session over TCP socket
// Handles: encryption, HMAC, sequence numbers, timestamps
class Session {
public:
    Session(int sockfd, const crypto::DerivedKeys& keys);
    ~Session();
    
    // Non-copyable
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    
    // Send encrypted message
    // Returns true on success
    bool send(const std::string& json_payload);
    
    // Receive and decrypt message
    // Returns decrypted JSON string on success
    std::optional<std::string> recv();
    
    // Get/set challenge (for bank/atm handshake)
    void set_challenge(const secure::SecureBuffer& challenge);
    const secure::SecureBuffer& get_challenge() const;
    
    // Check if session is valid
    bool is_valid() const { return valid_; }
    
private:
    int sockfd_;
    crypto::DerivedKeys keys_;
    uint64_t send_seq_;
    uint64_t recv_seq_;
    secure::SecureBuffer challenge_;
    bool valid_;
    
    // Build wire frame: SeqNo | Nonce | Ciphertext+Tag | Timestamp | HMAC
    std::optional<secure::SecureBuffer> build_frame(const std::string& payload);
    
    // Parse and verify wire frame
    std::optional<std::string> parse_frame(const secure::SecureBuffer& frame);
    
    // Get current timestamp
    static uint64_t current_timestamp();
    
    // Verify timestamp is within window
    static bool verify_timestamp(uint64_t ts);
};

} // namespace protocol

#endif // PROTOCOL_SESSION_HPP

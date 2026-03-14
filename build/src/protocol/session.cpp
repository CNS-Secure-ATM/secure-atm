#include "protocol/session.hpp"
#include "protocol/framing.hpp"
#include "crypto/aes_gcm.hpp"
#include "crypto/hmac.hpp"
#include <chrono>
#include <cstring>

namespace protocol {

// Wire frame layout:
// [SeqNo: 8B] [Nonce: 12B] [Ciphertext+Tag: var] [Timestamp: 8B] [HMAC: 32B]
// HMAC covers: SeqNo || Nonce || Ciphertext+Tag || Timestamp

constexpr size_t FRAME_HEADER_SIZE = secure::SEQNO_SIZE + secure::NONCE_SIZE;
constexpr size_t FRAME_FOOTER_SIZE = secure::TIMESTAMP_SIZE + secure::HMAC_SIZE;
constexpr size_t MIN_FRAME_SIZE = FRAME_HEADER_SIZE + secure::TAG_SIZE + FRAME_FOOTER_SIZE;

Session::Session(int sockfd, const crypto::DerivedKeys& keys)
    : sockfd_(sockfd)
    , keys_(keys)
    , send_seq_(0)
    , recv_seq_(0)
    , valid_(true)
{
    if (!keys_.valid()) {
        valid_ = false;
    }
    // Set 10-second timeout
    if (!set_socket_timeout(sockfd_, secure::TIMEOUT_SECONDS)) {
        valid_ = false;
    }
}

Session::~Session() {
    keys_.clear();
    challenge_.clear();
}

void Session::set_challenge(const secure::SecureBuffer& challenge) {
    challenge_ = challenge;
}

const secure::SecureBuffer& Session::get_challenge() const {
    return challenge_;
}

uint64_t Session::current_timestamp() {
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()
        ).count()
    );
}

bool Session::verify_timestamp(uint64_t ts) {
    uint64_t now = current_timestamp();
    int64_t diff = static_cast<int64_t>(now) - static_cast<int64_t>(ts);
    return diff >= -secure::TIMESTAMP_WINDOW && diff <= secure::TIMESTAMP_WINDOW;
}

std::optional<secure::SecureBuffer> Session::build_frame(const std::string& payload) {
    // Encrypt payload
    secure::SecureBuffer plaintext(
        reinterpret_cast<const uint8_t*>(payload.data()),
        payload.size()
    );
    
    auto encrypted = crypto::aes_gcm_encrypt(keys_.k_enc, plaintext);
    if (!encrypted) {
        return std::nullopt;
    }
    
    // Build frame: SeqNo || Nonce || Ciphertext+Tag || Timestamp
    size_t data_len = secure::SEQNO_SIZE + encrypted->nonce.size() + 
                      encrypted->ciphertext.size() + secure::TIMESTAMP_SIZE;
    secure::SecureBuffer frame_data(data_len);
    
    size_t offset = 0;
    
    // Write sequence number
    write_be64(frame_data.data() + offset, send_seq_);
    offset += secure::SEQNO_SIZE;
    
    // Write nonce
    std::memcpy(frame_data.data() + offset, encrypted->nonce.data(), encrypted->nonce.size());
    offset += encrypted->nonce.size();
    
    // Write ciphertext + tag
    std::memcpy(frame_data.data() + offset, encrypted->ciphertext.data(), encrypted->ciphertext.size());
    offset += encrypted->ciphertext.size();
    
    // Write timestamp
    uint64_t ts = current_timestamp();
    write_be64(frame_data.data() + offset, ts);
    
    // Compute HMAC over frame_data
    auto hmac = crypto::hmac_sha256(keys_.k_mac, frame_data);
    if (hmac.empty()) {
        return std::nullopt;
    }
    
    // Final frame: frame_data || HMAC
    secure::SecureBuffer final_frame(data_len + secure::HMAC_SIZE);
    std::memcpy(final_frame.data(), frame_data.data(), data_len);
    std::memcpy(final_frame.data() + data_len, hmac.data(), secure::HMAC_SIZE);
    
    send_seq_++;
    return final_frame;
}

std::optional<std::string> Session::parse_frame(const secure::SecureBuffer& frame) {
    if (frame.size() < MIN_FRAME_SIZE) {
        return std::nullopt;
    }
    
    size_t data_len = frame.size() - secure::HMAC_SIZE;
    
    // Verify HMAC first (before any parsing)
    secure::SecureBuffer expected_hmac = crypto::hmac_sha256(
        keys_.k_mac, frame.data(), data_len
    );
    secure::SecureBuffer actual_hmac(
        frame.data() + data_len, secure::HMAC_SIZE
    );
    
    if (!crypto::hmac_verify(expected_hmac, actual_hmac)) {
        return std::nullopt;
    }
    
    // Parse frame data
    size_t offset = 0;
    
    // Read and verify sequence number
    uint64_t seq = read_be64(frame.data() + offset);
    if (seq != recv_seq_) {
        return std::nullopt;
    }
    offset += secure::SEQNO_SIZE;
    
    // Read nonce
    secure::SecureBuffer nonce(frame.data() + offset, secure::NONCE_SIZE);
    offset += secure::NONCE_SIZE;
    
    // Calculate ciphertext length
    size_t ct_len = data_len - secure::SEQNO_SIZE - secure::NONCE_SIZE - secure::TIMESTAMP_SIZE;
    if (ct_len < secure::TAG_SIZE) {
        return std::nullopt;
    }
    
    // Read ciphertext
    secure::SecureBuffer ciphertext(frame.data() + offset, ct_len);
    offset += ct_len;
    
    // Read and verify timestamp
    uint64_t ts = read_be64(frame.data() + offset);
    if (!verify_timestamp(ts)) {
        return std::nullopt;
    }
    
    // Decrypt
    auto plaintext = crypto::aes_gcm_decrypt(keys_.k_enc, nonce, ciphertext);
    if (!plaintext) {
        return std::nullopt;
    }
    
    recv_seq_++;
    return std::string(reinterpret_cast<const char*>(plaintext->data()), plaintext->size());
}

bool Session::send(const std::string& json_payload) {
    if (!valid_) {
        return false;
    }
    
    auto frame = build_frame(json_payload);
    if (!frame) {
        valid_ = false;
        return false;
    }
    
    if (!write_frame(sockfd_, *frame)) {
        valid_ = false;
        return false;
    }
    
    return true;
}

std::optional<std::string> Session::recv() {
    if (!valid_) {
        return std::nullopt;
    }
    
    auto frame = read_frame(sockfd_);
    if (!frame) {
        valid_ = false;
        return std::nullopt;
    }
    
    auto payload = parse_frame(*frame);
    if (!payload) {
        valid_ = false;
        return std::nullopt;
    }
    
    return payload;
}

} // namespace protocol

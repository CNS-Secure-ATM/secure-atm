#ifndef COMMON_TYPES_HPP
#define COMMON_TYPES_HPP

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <openssl/crypto.h>

namespace secure {

// Constants
constexpr size_t KEY_SIZE = 32;          // 256 bits
constexpr size_t NONCE_SIZE = 12;        // 96 bits for AES-GCM
constexpr size_t TAG_SIZE = 16;          // 128 bits
constexpr size_t HMAC_SIZE = 32;         // SHA-256
constexpr size_t CHALLENGE_SIZE = 32;    // 256 bits
constexpr size_t SEQNO_SIZE = 8;         // uint64
constexpr size_t TIMESTAMP_SIZE = 8;     // uint64
constexpr size_t LENGTH_PREFIX_SIZE = 4; // uint32

constexpr uint32_t MAX_MESSAGE_SIZE = 8192; // 8KB max message
constexpr int TIMEOUT_SECONDS = 10;
constexpr int64_t TIMESTAMP_WINDOW = 30;    // +-30 seconds

} // namespace secure

#endif // COMMON_TYPES_HPP
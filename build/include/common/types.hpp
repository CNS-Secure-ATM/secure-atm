#ifndef COMMON_TYPES_HPP
#define COMMON_TYPES_HPP

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <openssl/crypto.h>

namespace secure 
{

// RAII wrapper for sensitive data - securely wipes memory on destruction
class SecureBuffer 
{

private:
    std::vector<uint8_t> data_;
    
    static int hex_to_nibble(char c) 
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

public:
    SecureBuffer() = default;
    
    explicit SecureBuffer(size_t size) 
    : 
    data_(size, 0) 
    {}
    
    SecureBuffer(const uint8_t* src, size_t size) 
    : 
    data_(src, src + size) 
    {}
    
    SecureBuffer(const SecureBuffer& other) 
    : 
    data_(other.data_) {}
    
    SecureBuffer(SecureBuffer&& other) noexcept 
    : 
    data_(std::move(other.data_))
    {
        other.data_.clear();
    }
    
    SecureBuffer& operator=(const SecureBuffer& other) 
    {
        if (this != &other) 
        {
            clear();
            data_ = other.data_;
        }
        return *this;
    }
    
    SecureBuffer& operator=(SecureBuffer&& other) noexcept 
    {
        if (this != &other) 
        {
            clear();
            data_ = std::move(other.data_);
            other.data_.clear();
        }
        return *this;
    }
    
    ~SecureBuffer() 
    {
        clear();
    }
    
    void clear() 
    {
        if (!data_.empty()) 
        {
            OPENSSL_cleanse(data_.data(), data_.size());
            data_.clear();
        }
    }
    
    void resize(size_t size) 
    {
        if (size < data_.size()) 
        {
            OPENSSL_cleanse(data_.data() + size, data_.size() - size);
        }
        data_.resize(size, 0);
    }
    
    uint8_t* data() { return data_.data(); }
    const uint8_t* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }
    
    uint8_t& operator[](size_t idx) { return data_[idx]; }
    const uint8_t& operator[](size_t idx) const { return data_[idx]; }
    
    // Append data
    void append(const uint8_t* src, size_t len) 
    {
        size_t old_size = data_.size();
        data_.resize(old_size + len);
        std::memcpy(data_.data() + old_size, src, len);
    }
    
    // Convert to hex string (for card files, etc.)
    std::string to_hex() const 
    {
        static const char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(data_.size() * 2);
        for (uint8_t byte : data_) {
            result.push_back(hex_chars[(byte >> 4) & 0x0F]);
            result.push_back(hex_chars[byte & 0x0F]);
        }
        return result;
    }
    
    // Create from hex string
    static SecureBuffer from_hex(const std::string& hex) 
    {
        if (hex.size() % 2 != 0) 
        {
            return SecureBuffer();
        }
        SecureBuffer result(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) 
        {
            int high = hex_to_nibble(hex[i]);
            int low = hex_to_nibble(hex[i + 1]);
            if (high < 0 || low < 0) 
            {
                return SecureBuffer();
            }
            result[i / 2] = static_cast<uint8_t>((high << 4) | low);
        }
        return result;
    }
};

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
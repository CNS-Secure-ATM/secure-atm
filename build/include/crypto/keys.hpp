#ifndef CRYPTO_KEYS_HPP
#define CRYPTO_KEYS_HPP

#include "common/types.hpp"
#include <string>

namespace crypto 
{

// Key derivation context strings
constexpr const char* SALT_ENC = "secure-atm-enc";
constexpr const char* SALT_MAC = "secure-atm-mac";
constexpr const char* SALT_CARD = "secure-atm-card";

constexpr const char* INFO_ENC = "enc";
constexpr const char* INFO_MAC = "mac";
constexpr const char* INFO_CARD = "card";

// Holds derived keys from master secret
struct DerivedKeys 
{
    secure::SecureBuffer k_enc;   // AES-256 encryption key
    secure::SecureBuffer k_mac;   // HMAC-SHA256 key
    secure::SecureBuffer k_card;  // Card secret derivation key
    
    bool valid() const 
    {
        return k_enc.size() == secure::KEY_SIZE && 
               k_mac.size() == secure::KEY_SIZE && 
               k_card.size() == secure::KEY_SIZE;
    }
    
    void clear() 
    {
        k_enc.clear();
        k_mac.clear();
        k_card.clear();
    }
};

// Generate a new master key (256 bits)
secure::SecureBuffer generate_master_key();

// Derive keys from master secret using HKDF-SHA256
// Returns DerivedKeys with all three keys derived
DerivedKeys derive_keys(const secure::SecureBuffer& master);

// Single HKDF derivation
secure::SecureBuffer hkdf_sha256(
    const secure::SecureBuffer& ikm,
    const std::string& salt,
    const std::string& info,
    size_t length
);

} // namespace crypto

#endif // CRYPTO_KEYS_HPP

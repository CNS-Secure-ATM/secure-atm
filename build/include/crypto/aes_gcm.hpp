#ifndef CRYPTO_AES_GCM_HPP
#define CRYPTO_AES_GCM_HPP

#include "common/types.hpp"
#include <optional>

namespace crypto 
{

// AES-256-GCM encryption result
struct EncryptedData 
{
    secure::SecureBuffer nonce;      // 12 bytes
    secure::SecureBuffer ciphertext; // includes GCM tag at end
    
    bool valid() const 
    {
        return nonce.size() == secure::NONCE_SIZE && 
               ciphertext.size() >= secure::TAG_SIZE;
    }
};

// Encrypt data using AES-256-GCM
// Returns encrypted data with randomly generated nonce
// AAD (Additional Authenticated Data) is optional but bound to ciphertext
std::optional<EncryptedData> aes_gcm_encrypt(
    const secure::SecureBuffer& key,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* aad = nullptr,
    size_t aad_len = 0
);

// Convenience overload for SecureBuffer
std::optional<EncryptedData> aes_gcm_encrypt(
    const secure::SecureBuffer& key,
    const secure::SecureBuffer& plaintext,
    const uint8_t* aad = nullptr,
    size_t aad_len = 0
);

// Decrypt data using AES-256-GCM
// Returns plaintext on success, empty on failure (tag mismatch, etc.)
std::optional<secure::SecureBuffer> aes_gcm_decrypt(
    const secure::SecureBuffer& key,
    const secure::SecureBuffer& nonce,
    const secure::SecureBuffer& ciphertext,  // includes tag
    const uint8_t* aad = nullptr,
    size_t aad_len = 0
);

} // namespace crypto

#endif // CRYPTO_AES_GCM_HPP

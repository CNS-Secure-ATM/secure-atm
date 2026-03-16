#include "crypto/aes_gcm.hpp"
#include "crypto/random.hpp"
#include <openssl/evp.h>

namespace crypto {

std::optional<EncryptedData> aes_gcm_encrypt(
    const secure::SecureBuffer& key,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* aad,
    size_t aad_len
) 
{
    if (key.size() != secure::KEY_SIZE) 
    {
        return std::nullopt;
    }
    
    // Generate random nonce
    secure::SecureBuffer nonce = random_bytes(secure::NONCE_SIZE);
    if (nonce.empty()) 
    {
        return std::nullopt;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) 
    {
        return std::nullopt;
    }
    
    EncryptedData result;
    result.nonce = std::move(nonce);
    result.ciphertext.resize(plaintext_len + secure::TAG_SIZE);
    
    bool success = false;
    do {
        // EVP_EncryptInit_ex(ctx, type, engine, key, iv)
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, secure::NONCE_SIZE, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.nonce.data()) != 1) break;
        
        // Add AAD if provided
        int len = 0;
        if (aad != nullptr && aad_len > 0) 
        {
            // EVP_EncryptUpdate(ctx, out, outlen, in, inlen)
            if (EVP_EncryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) != 1) break;
        }
        
        // Encrypt plaintext
        if (plaintext_len > 0) 
        {
            if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, 
                plaintext, static_cast<int>(plaintext_len)) != 1) break;
        }
        
        // Finalize
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &final_len) != 1) break;
        
        // Get tag and append to ciphertext
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, secure::TAG_SIZE, 
            result.ciphertext.data() + plaintext_len) != 1) break;
        
        success = true;
    } while (false);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (!success) 
    {
        return std::nullopt;
    }
    return result;
}

std::optional<EncryptedData> aes_gcm_encrypt(
    const secure::SecureBuffer& key,
    const secure::SecureBuffer& plaintext,
    const uint8_t* aad,
    size_t aad_len
) 
{
    return aes_gcm_encrypt(key, plaintext.data(), plaintext.size(), aad, aad_len);
}

std::optional<secure::SecureBuffer> aes_gcm_decrypt(
    const secure::SecureBuffer& key,
    const secure::SecureBuffer& nonce,
    const secure::SecureBuffer& ciphertext,
    const uint8_t* aad,
    size_t aad_len
) 
{
    if (key.size() != secure::KEY_SIZE || 
        nonce.size() != secure::NONCE_SIZE ||
        ciphertext.size() < secure::TAG_SIZE) {
        return std::nullopt;
    }
    
    size_t ct_len = ciphertext.size() - secure::TAG_SIZE;
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) 
    {
        return std::nullopt;
    }
    
    secure::SecureBuffer plaintext(ct_len);
    bool success = false;
    
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, secure::NONCE_SIZE, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) break;
        
        // Add AAD if provided
        int len = 0;
        if (aad != nullptr && aad_len > 0) 
        {
            if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) != 1) break;
        }
        
        // Decrypt ciphertext
        if (ct_len > 0) 
        {
            if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                ciphertext.data(), static_cast<int>(ct_len)) != 1) break;
        }
        
        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, secure::TAG_SIZE, 
            const_cast<uint8_t*>(ciphertext.data() + ct_len)) != 1) break;
        
        // Verify tag
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) != 1) break;
        
        success = true;
    } while (false);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (!success) 
    {
        return std::nullopt;
    }
    return plaintext;
}

} // namespace crypto

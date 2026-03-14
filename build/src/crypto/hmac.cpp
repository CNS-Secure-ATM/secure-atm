#include "crypto/hmac.hpp"
#include <openssl/hmac.h>
#include <openssl/crypto.h>

namespace crypto 
{

secure::SecureBuffer hmac_sha256(
    const secure::SecureBuffer& key,
    const uint8_t* data,
    size_t data_len
) 
{
    secure::SecureBuffer result(secure::HMAC_SIZE);
    unsigned int len = secure::HMAC_SIZE;
    
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             data, data_len, result.data(), &len) == nullptr) 
    {
        result.clear();
    }
    
    return result;
}

secure::SecureBuffer hmac_sha256(
    const secure::SecureBuffer& key,
    const secure::SecureBuffer& data
) 
{
    return hmac_sha256(key, data.data(), data.size());
}

secure::SecureBuffer hmac_sha256(
    const secure::SecureBuffer& key,
    const std::string& data
) 
{
    return hmac_sha256(key, reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

bool hmac_verify(
    const secure::SecureBuffer& expected,
    const secure::SecureBuffer& actual
) 
{
    if (expected.size() != actual.size() || expected.size() != secure::HMAC_SIZE) {
        return false;
    }
    // Constant-time comparison
    return CRYPTO_memcmp(expected.data(), actual.data(), secure::HMAC_SIZE) == 0;
}

secure::SecureBuffer compute_card_secret(
    const secure::SecureBuffer& k_card,
    const std::string& account_name
) 
{
    return hmac_sha256(k_card, account_name);
}

secure::SecureBuffer compute_card_proof(
    const secure::SecureBuffer& card_secret,
    const secure::SecureBuffer& challenge
) 
{
    return hmac_sha256(card_secret, challenge);
}

} // namespace crypto

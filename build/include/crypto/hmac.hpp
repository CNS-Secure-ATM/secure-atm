#ifndef CRYPTO_HMAC_HPP
#define CRYPTO_HMAC_HPP

#include "common/types.hpp"
#include <string>

namespace crypto 
{

// Compute HMAC-SHA256
secure::SecureBuffer hmac_sha256(
    const secure::SecureBuffer& key,
    const uint8_t* data,
    size_t data_len
);

// Convenience overload
secure::SecureBuffer hmac_sha256(
    const secure::SecureBuffer& key,
    const secure::SecureBuffer& data
);

// HMAC over string data (for card secret derivation)
secure::SecureBuffer hmac_sha256(
    const secure::SecureBuffer& key,
    const std::string& data
);

// Constant-time HMAC comparison
// Returns true if MACs match
bool hmac_verify(
    const secure::SecureBuffer& expected,
    const secure::SecureBuffer& actual
);

// Compute card secret: HMAC(K_card, account_name)
secure::SecureBuffer compute_card_secret(
    const secure::SecureBuffer& k_card,
    const std::string& account_name
);

// Compute card proof: HMAC(card_secret, challenge)
secure::SecureBuffer compute_card_proof(
    const secure::SecureBuffer& card_secret,
    const secure::SecureBuffer& challenge
);

} // namespace crypto

#endif // CRYPTO_HMAC_HPP

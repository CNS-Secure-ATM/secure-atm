#ifndef CRYPTO_RANDOM_HPP
#define CRYPTO_RANDOM_HPP

#include "common/types.hpp"

namespace crypto 
{

// Generate cryptographically secure random bytes
// Returns false on failure
bool random_bytes(uint8_t* buffer, size_t size);

// Generate random bytes into SecureBuffer
secure::SecureBuffer random_bytes(size_t size);

} // namespace crypto

#endif // CRYPTO_RANDOM_HPP

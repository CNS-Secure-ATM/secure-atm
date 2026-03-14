#include "crypto/random.hpp"
#include <openssl/rand.h>

namespace crypto 
{

bool random_bytes(uint8_t* buffer, size_t size) 
{
    if (buffer == nullptr || size == 0) 
    {
        return false;
    }
    return RAND_bytes(buffer, static_cast<int>(size)) == 1;
}

secure::SecureBuffer random_bytes(size_t size) 
{
    secure::SecureBuffer buf(size);
    if (!random_bytes(buf.data(), size)) 
    {
        buf.clear();
    }
    return buf;
}

} // namespace crypto

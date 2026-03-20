#include "crypto/keys.hpp"
#include "crypto/random.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace crypto 
{

secure::SecureBuffer generate_master_key() 
{
    return random_bytes(secure::KEY_SIZE);
}

secure::SecureBuffer hkdf_sha256(
    const secure::SecureBuffer& ikm,
    const std::string& salt,
    const std::string& info,
    size_t length
) 
{
    secure::SecureBuffer output(length);
    
    // https://docs.openssl.org/3.5/man3/EVP_PKEY_CTX_set_hkdf_md/#string-ctrls
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (ctx == nullptr) 
    {
        output.clear();
        return output;
    }
    
    bool success = false;
    do {
        /*
        https://docs.openssl.org/3.5/man3/EVP_PKEY_derive/
        int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
        int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
        */
        if (EVP_PKEY_derive_init(ctx) <= 0) break;

        /* 
        https://docs.openssl.org/3.5/man3/EVP_PKEY_CTX_set_hkdf_md/
        int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX *pctx, const EVP_MD *md); 
        int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *pctx, unsigned char *salt, int saltlen);
        int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *pctx, unsigned char *key, int keylen);
        int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *pctx, unsigned char *info, int infolen);
        */
        if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) break;
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, 
            reinterpret_cast<const unsigned char*>(salt.data()), 
            static_cast<int>(salt.size())) <= 0) break;
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, 
            ikm.data(), 
            static_cast<int>(ikm.size())) <= 0) break;
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, 
            reinterpret_cast<const unsigned char*>(info.data()), 
            static_cast<int>(info.size())) <= 0) break;
        
        size_t outlen = length;
        if (EVP_PKEY_derive(ctx, output.data(), &outlen) <= 0) break;
        
        success = (outlen == length);
    } while (false);
    
    EVP_PKEY_CTX_free(ctx);
    
    if (!success) 
    {
        output.clear();
    }
    return output;
}

DerivedKeys derive_keys(const secure::SecureBuffer& master) 
{
    DerivedKeys keys;
    
    if (master.size() != secure::KEY_SIZE) 
    {
        return keys;
    }
    
    keys.k_enc = hkdf_sha256(master, SALT_ENC, INFO_ENC, secure::KEY_SIZE);
    keys.k_mac = hkdf_sha256(master, SALT_MAC, INFO_MAC, secure::KEY_SIZE);
    keys.k_card = hkdf_sha256(master, SALT_CARD, INFO_CARD, secure::KEY_SIZE);
    
    if (!keys.valid()) 
    {
        keys.clear();
    }
    
    return keys;
}

} // namespace crypto

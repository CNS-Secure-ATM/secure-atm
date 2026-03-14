// Crypto unit tests
#include "test_framework.hpp"
#include "common/types.hpp"
#include "crypto/random.hpp"
#include "crypto/keys.hpp"
#include "crypto/aes_gcm.hpp"
#include "crypto/hmac.hpp"
#include <cstring>

// ============================================================================
// SecureBuffer tests
// ============================================================================

TEST(secure_buffer_basic) {
    secure::SecureBuffer buf(32);
    EXPECT_EQ(buf.size(), 32UL);
    EXPECT_FALSE(buf.empty());
    
    secure::SecureBuffer empty;
    EXPECT_TRUE(empty.empty());
    EXPECT_EQ(empty.size(), 0UL);
    return true;
}

TEST(secure_buffer_hex) {
    secure::SecureBuffer buf(4);
    buf[0] = 0xde;
    buf[1] = 0xad;
    buf[2] = 0xbe;
    buf[3] = 0xef;
    
    EXPECT_EQ(buf.to_hex(), "deadbeef");
    
    auto parsed = secure::SecureBuffer::from_hex("cafebabe");
    EXPECT_EQ(parsed.size(), 4UL);
    EXPECT_EQ(parsed[0], 0xca);
    EXPECT_EQ(parsed[1], 0xfe);
    EXPECT_EQ(parsed[2], 0xba);
    EXPECT_EQ(parsed[3], 0xbe);
    return true;
}

TEST(secure_buffer_hex_invalid) {
    // Odd length
    auto buf1 = secure::SecureBuffer::from_hex("abc");
    EXPECT_TRUE(buf1.empty());
    
    // Invalid characters
    auto buf2 = secure::SecureBuffer::from_hex("ghij");
    EXPECT_TRUE(buf2.empty());
    
    // Empty
    auto buf3 = secure::SecureBuffer::from_hex("");
    EXPECT_TRUE(buf3.empty());
    return true;
}

TEST(secure_buffer_copy) {
    secure::SecureBuffer orig(16);
    crypto::random_bytes(orig.data(), orig.size());
    
    secure::SecureBuffer copy = orig;
    EXPECT_EQ(copy.size(), orig.size());
    EXPECT_TRUE(std::memcmp(copy.data(), orig.data(), orig.size()) == 0);
    return true;
}

TEST(secure_buffer_move) {
    secure::SecureBuffer orig(16);
    crypto::random_bytes(orig.data(), orig.size());
    
    secure::SecureBuffer moved = std::move(orig);
    EXPECT_EQ(moved.size(), 16UL);
    EXPECT_TRUE(orig.empty());  // Original should be cleared
    return true;
}

// ============================================================================
// Random generation tests
// ============================================================================

TEST(random_bytes_basic) {
    auto buf1 = crypto::random_bytes(32);
    auto buf2 = crypto::random_bytes(32);
    
    EXPECT_EQ(buf1.size(), 32UL);
    EXPECT_EQ(buf2.size(), 32UL);
    
    // Should be different (extremely unlikely to be same)
    bool same = std::memcmp(buf1.data(), buf2.data(), 32) == 0;
    EXPECT_FALSE(same);
    return true;
}

TEST(random_bytes_zero_size) {
    auto buf = crypto::random_bytes(0);
    EXPECT_TRUE(buf.empty());
    return true;
}

TEST(random_bytes_fill) {
    uint8_t buf1[16] = {0};
    uint8_t buf2[16] = {0};
    
    EXPECT_TRUE(crypto::random_bytes(buf1, 16));
    EXPECT_TRUE(crypto::random_bytes(buf2, 16));
    
    // Should be different
    bool same = std::memcmp(buf1, buf2, 16) == 0;
    EXPECT_FALSE(same);
    return true;
}

// ============================================================================
// Key derivation tests
// ============================================================================

TEST(derive_keys_basic) {
    auto master = crypto::random_bytes(secure::KEY_SIZE);
    auto keys = crypto::derive_keys(master);
    
    EXPECT_TRUE(keys.valid());
    EXPECT_EQ(keys.k_enc.size(), secure::KEY_SIZE);
    EXPECT_EQ(keys.k_mac.size(), secure::KEY_SIZE);
    EXPECT_EQ(keys.k_card.size(), secure::KEY_SIZE);
    return true;
}

TEST(derive_keys_deterministic) {
    auto master = crypto::random_bytes(secure::KEY_SIZE);
    
    auto keys1 = crypto::derive_keys(master);
    auto keys2 = crypto::derive_keys(master);
    
    // Same master key should produce same derived keys
    EXPECT_TRUE(std::memcmp(keys1.k_enc.data(), keys2.k_enc.data(), secure::KEY_SIZE) == 0);
    EXPECT_TRUE(std::memcmp(keys1.k_mac.data(), keys2.k_mac.data(), secure::KEY_SIZE) == 0);
    EXPECT_TRUE(std::memcmp(keys1.k_card.data(), keys2.k_card.data(), secure::KEY_SIZE) == 0);
    return true;
}

TEST(derive_keys_different_master) {
    auto master1 = crypto::random_bytes(secure::KEY_SIZE);
    auto master2 = crypto::random_bytes(secure::KEY_SIZE);
    
    auto keys1 = crypto::derive_keys(master1);
    auto keys2 = crypto::derive_keys(master2);
    
    // Different master keys should produce different derived keys
    bool enc_same = std::memcmp(keys1.k_enc.data(), keys2.k_enc.data(), secure::KEY_SIZE) == 0;
    EXPECT_FALSE(enc_same);
    return true;
}

TEST(derive_keys_unique_outputs) {
    auto master = crypto::random_bytes(secure::KEY_SIZE);
    auto keys = crypto::derive_keys(master);
    
    // All derived keys should be different from each other
    bool enc_mac = std::memcmp(keys.k_enc.data(), keys.k_mac.data(), secure::KEY_SIZE) == 0;
    bool enc_card = std::memcmp(keys.k_enc.data(), keys.k_card.data(), secure::KEY_SIZE) == 0;
    bool mac_card = std::memcmp(keys.k_mac.data(), keys.k_card.data(), secure::KEY_SIZE) == 0;
    
    EXPECT_FALSE(enc_mac);
    EXPECT_FALSE(enc_card);
    EXPECT_FALSE(mac_card);
    return true;
}

// ============================================================================
// AES-GCM tests
// ============================================================================

TEST(aes_gcm_encrypt_decrypt) {
    auto key = crypto::random_bytes(secure::KEY_SIZE);
    secure::SecureBuffer plaintext(100);
    crypto::random_bytes(plaintext.data(), plaintext.size());
    
    auto encrypted = crypto::aes_gcm_encrypt(key, plaintext);
    EXPECT_TRUE(encrypted.has_value());
    EXPECT_TRUE(encrypted->valid());
    EXPECT_EQ(encrypted->nonce.size(), secure::NONCE_SIZE);
    
    auto decrypted = crypto::aes_gcm_decrypt(key, encrypted->nonce, encrypted->ciphertext);
    EXPECT_TRUE(decrypted.has_value());
    EXPECT_EQ(decrypted->size(), plaintext.size());
    EXPECT_TRUE(std::memcmp(decrypted->data(), plaintext.data(), plaintext.size()) == 0);
    return true;
}

TEST(aes_gcm_with_aad) {
    auto key = crypto::random_bytes(secure::KEY_SIZE);
    secure::SecureBuffer plaintext(64);
    crypto::random_bytes(plaintext.data(), plaintext.size());
    
    const char* aad = "additional data";
    size_t aad_len = std::strlen(aad);
    
    auto encrypted = crypto::aes_gcm_encrypt(key, plaintext, 
        reinterpret_cast<const uint8_t*>(aad), aad_len);
    EXPECT_TRUE(encrypted.has_value());
    
    // Decrypt with same AAD
    auto decrypted = crypto::aes_gcm_decrypt(key, encrypted->nonce, encrypted->ciphertext,
        reinterpret_cast<const uint8_t*>(aad), aad_len);
    EXPECT_TRUE(decrypted.has_value());
    
    // Decrypt with wrong AAD should fail
    const char* wrong_aad = "wrong data";
    auto bad_decrypt = crypto::aes_gcm_decrypt(key, encrypted->nonce, encrypted->ciphertext,
        reinterpret_cast<const uint8_t*>(wrong_aad), std::strlen(wrong_aad));
    EXPECT_FALSE(bad_decrypt.has_value());
    return true;
}

TEST(aes_gcm_wrong_key) {
    auto key1 = crypto::random_bytes(secure::KEY_SIZE);
    auto key2 = crypto::random_bytes(secure::KEY_SIZE);
    
    secure::SecureBuffer plaintext(32);
    crypto::random_bytes(plaintext.data(), plaintext.size());
    
    auto encrypted = crypto::aes_gcm_encrypt(key1, plaintext);
    EXPECT_TRUE(encrypted.has_value());
    
    // Decrypt with wrong key should fail
    auto decrypted = crypto::aes_gcm_decrypt(key2, encrypted->nonce, encrypted->ciphertext);
    EXPECT_FALSE(decrypted.has_value());
    return true;
}

TEST(aes_gcm_tampered_ciphertext) {
    auto key = crypto::random_bytes(secure::KEY_SIZE);
    secure::SecureBuffer plaintext(32);
    crypto::random_bytes(plaintext.data(), plaintext.size());
    
    auto encrypted = crypto::aes_gcm_encrypt(key, plaintext);
    EXPECT_TRUE(encrypted.has_value());
    
    // Tamper with ciphertext
    encrypted->ciphertext[0] ^= 0xFF;
    
    auto decrypted = crypto::aes_gcm_decrypt(key, encrypted->nonce, encrypted->ciphertext);
    EXPECT_FALSE(decrypted.has_value());
    return true;
}

TEST(aes_gcm_empty_plaintext) {
    auto key = crypto::random_bytes(secure::KEY_SIZE);
    secure::SecureBuffer plaintext;  // empty
    
    auto encrypted = crypto::aes_gcm_encrypt(key, plaintext);
    EXPECT_TRUE(encrypted.has_value());
    
    auto decrypted = crypto::aes_gcm_decrypt(key, encrypted->nonce, encrypted->ciphertext);
    EXPECT_TRUE(decrypted.has_value());
    EXPECT_TRUE(decrypted->empty());
    return true;
}

// ============================================================================
// HMAC tests
// ============================================================================

TEST(hmac_deterministic) {
    auto key = crypto::random_bytes(secure::KEY_SIZE);
    const char* data = "test data";
    
    auto hmac1 = crypto::hmac_sha256(key, std::string(data));
    auto hmac2 = crypto::hmac_sha256(key, std::string(data));
    
    EXPECT_EQ(hmac1.size(), static_cast<size_t>(secure::HMAC_SIZE));
    EXPECT_TRUE(std::memcmp(hmac1.data(), hmac2.data(), secure::HMAC_SIZE) == 0);
    return true;
}

TEST(hmac_different_data) {
    auto key = crypto::random_bytes(secure::KEY_SIZE);
    
    auto hmac1 = crypto::hmac_sha256(key, std::string("data1"));
    auto hmac2 = crypto::hmac_sha256(key, std::string("data2"));
    
    bool same = std::memcmp(hmac1.data(), hmac2.data(), secure::HMAC_SIZE) == 0;
    EXPECT_FALSE(same);
    return true;
}

TEST(hmac_different_keys) {
    auto key1 = crypto::random_bytes(secure::KEY_SIZE);
    auto key2 = crypto::random_bytes(secure::KEY_SIZE);
    const char* data = "test data";
    
    auto hmac1 = crypto::hmac_sha256(key1, std::string(data));
    auto hmac2 = crypto::hmac_sha256(key2, std::string(data));
    
    bool same = std::memcmp(hmac1.data(), hmac2.data(), secure::HMAC_SIZE) == 0;
    EXPECT_FALSE(same);
    return true;
}

TEST(hmac_verify_correct) {
    auto key = crypto::random_bytes(secure::KEY_SIZE);
    auto data = crypto::random_bytes(64);
    
    auto hmac = crypto::hmac_sha256(key, data);
    EXPECT_TRUE(crypto::hmac_verify(hmac, hmac));
    return true;
}

TEST(hmac_verify_wrong) {
    auto key = crypto::random_bytes(secure::KEY_SIZE);
    auto data = crypto::random_bytes(64);
    
    auto hmac1 = crypto::hmac_sha256(key, data);
    auto hmac2 = crypto::random_bytes(secure::HMAC_SIZE);

    EXPECT_FALSE(crypto::hmac_verify(hmac1, hmac2));
    return true;
}

// ============================================================================
// Card secret/proof tests
// ============================================================================

TEST(card_secret_deterministic) {
    auto k_card = crypto::random_bytes(secure::KEY_SIZE);
    std::string account = "testuser";
    
    auto secret1 = crypto::compute_card_secret(k_card, account);
    auto secret2 = crypto::compute_card_secret(k_card, account);
    
    EXPECT_EQ(secret1.size(), static_cast<size_t>(secure::KEY_SIZE));
    EXPECT_TRUE(std::memcmp(secret1.data(), secret2.data(), secure::KEY_SIZE) == 0);
    return true;
}

TEST(card_secret_different_accounts) {
    auto k_card = crypto::random_bytes(secure::KEY_SIZE);
    
    auto secret1 = crypto::compute_card_secret(k_card, "alice");
    auto secret2 = crypto::compute_card_secret(k_card, "bob");
    
    bool same = std::memcmp(secret1.data(), secret2.data(), secure::KEY_SIZE) == 0;
    EXPECT_FALSE(same);
    return true;
}

TEST(card_proof_deterministic) {
    auto card_secret = crypto::random_bytes(secure::KEY_SIZE);
    auto challenge = crypto::random_bytes(secure::CHALLENGE_SIZE);
    
    auto proof1 = crypto::compute_card_proof(card_secret, challenge);
    auto proof2 = crypto::compute_card_proof(card_secret, challenge);
    
    EXPECT_EQ(proof1.size(), static_cast<size_t>(secure::HMAC_SIZE));
    EXPECT_TRUE(std::memcmp(proof1.data(), proof2.data(), secure::HMAC_SIZE) == 0);
    return true;
}

TEST(card_proof_different_challenges) {
    auto card_secret = crypto::random_bytes(secure::KEY_SIZE);
    auto challenge1 = crypto::random_bytes(secure::CHALLENGE_SIZE);
    auto challenge2 = crypto::random_bytes(secure::CHALLENGE_SIZE);
    
    auto proof1 = crypto::compute_card_proof(card_secret, challenge1);
    auto proof2 = crypto::compute_card_proof(card_secret, challenge2);
    
    bool same = std::memcmp(proof1.data(), proof2.data(), secure::HMAC_SIZE) == 0;
    EXPECT_FALSE(same);
    return true;
}

int main() {
    return test::run_tests();
}

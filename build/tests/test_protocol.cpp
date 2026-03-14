// Protocol unit tests
#include "test_framework.hpp"
#include "common/types.hpp"
#include "protocol/framing.hpp"
#include "crypto/random.hpp"
#include <cstring>

// ============================================================================
// Big-endian encoding tests
// ============================================================================

TEST(encode_decode_be32) {
    uint8_t buf[4];
    
    protocol::write_be32(buf, 0x12345678);
    EXPECT_EQ(buf[0], 0x12);
    EXPECT_EQ(buf[1], 0x34);
    EXPECT_EQ(buf[2], 0x56);
    EXPECT_EQ(buf[3], 0x78);
    
    EXPECT_EQ(protocol::read_be32(buf), 0x12345678U);
    return true;
}

TEST(encode_decode_be64) {
    uint8_t buf[8];
    
    protocol::write_be64(buf, 0x123456789ABCDEF0ULL);
    EXPECT_EQ(buf[0], 0x12);
    EXPECT_EQ(buf[1], 0x34);
    EXPECT_EQ(buf[2], 0x56);
    EXPECT_EQ(buf[3], 0x78);
    EXPECT_EQ(buf[4], 0x9A);
    EXPECT_EQ(buf[5], 0xBC);
    EXPECT_EQ(buf[6], 0xDE);
    EXPECT_EQ(buf[7], 0xF0);
    
    EXPECT_EQ(protocol::read_be64(buf), 0x123456789ABCDEF0ULL);
    return true;
}

TEST(be32_roundtrip) {
    uint8_t buf[4];
    
    protocol::write_be32(buf, 0);
    EXPECT_EQ(protocol::read_be32(buf), 0U);
    
    protocol::write_be32(buf, 0xFFFFFFFF);
    EXPECT_EQ(protocol::read_be32(buf), 0xFFFFFFFFU);
    
    protocol::write_be32(buf, 0xDEADBEEF);
    EXPECT_EQ(protocol::read_be32(buf), 0xDEADBEEFU);
    return true;
}

TEST(be64_roundtrip) {
    uint8_t buf[8];
    
    protocol::write_be64(buf, 0);
    EXPECT_EQ(protocol::read_be64(buf), 0ULL);
    
    protocol::write_be64(buf, 0xFFFFFFFFFFFFFFFFULL);
    EXPECT_EQ(protocol::read_be64(buf), 0xFFFFFFFFFFFFFFFFULL);
    
    protocol::write_be64(buf, 0xCAFEBABEDEADBEEFULL);
    EXPECT_EQ(protocol::read_be64(buf), 0xCAFEBABEDEADBEEFULL);
    return true;
}

// ============================================================================
// Message size validation tests
// ============================================================================

TEST(message_size_valid) {
    // Messages up to MAX_MESSAGE_SIZE should be valid
    EXPECT_TRUE(secure::MAX_MESSAGE_SIZE <= 8192);  // Verify our constant
    return true;
}

TEST(constants_defined) {
    // Verify all key security constants are defined correctly
    EXPECT_EQ(secure::KEY_SIZE, 32UL);
    EXPECT_EQ(secure::NONCE_SIZE, 12UL);
    EXPECT_EQ(secure::TAG_SIZE, 16UL);
    EXPECT_EQ(secure::HMAC_SIZE, 32UL);
    EXPECT_EQ(secure::CHALLENGE_SIZE, 32UL);
    return true;
}

int main() {
    return test::run_tests();
}

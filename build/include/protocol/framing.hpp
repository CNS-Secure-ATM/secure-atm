#ifndef PROTOCOL_FRAMING_HPP
#define PROTOCOL_FRAMING_HPP

#include "common/types.hpp"
#include <optional>

namespace protocol {

// Read/write length-prefixed frames over a socket
// Frame format: [4-byte length (big-endian)] [payload]

// Read a complete frame from socket
// Returns empty on error or timeout
std::optional<secure::SecureBuffer> read_frame(int sockfd);

// Write a frame to socket
// Returns true on success
bool write_frame(int sockfd, const uint8_t* data, size_t len);
bool write_frame(int sockfd, const secure::SecureBuffer& data);

// Utility: read exactly n bytes
bool read_exact(int sockfd, uint8_t* buffer, size_t n);

// Utility: write exactly n bytes
bool write_exact(int sockfd, const uint8_t* buffer, size_t n);

// Set socket timeout
bool set_socket_timeout(int sockfd, int seconds);

// Big-endian conversion utilities
uint32_t read_be32(const uint8_t* buf);
void write_be32(uint8_t* buf, uint32_t val);
uint64_t read_be64(const uint8_t* buf);
void write_be64(uint8_t* buf, uint64_t val);

} // namespace protocol

#endif // PROTOCOL_FRAMING_HPP

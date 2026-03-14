#include "protocol/framing.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace protocol {

uint32_t read_be32(const uint8_t* buf) {
    return (static_cast<uint32_t>(buf[0]) << 24) |
           (static_cast<uint32_t>(buf[1]) << 16) |
           (static_cast<uint32_t>(buf[2]) << 8) |
           (static_cast<uint32_t>(buf[3]));
}

void write_be32(uint8_t* buf, uint32_t val) {
    buf[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>(val & 0xFF);
}

uint64_t read_be64(const uint8_t* buf) {
    return (static_cast<uint64_t>(buf[0]) << 56) |
           (static_cast<uint64_t>(buf[1]) << 48) |
           (static_cast<uint64_t>(buf[2]) << 40) |
           (static_cast<uint64_t>(buf[3]) << 32) |
           (static_cast<uint64_t>(buf[4]) << 24) |
           (static_cast<uint64_t>(buf[5]) << 16) |
           (static_cast<uint64_t>(buf[6]) << 8) |
           (static_cast<uint64_t>(buf[7]));
}

void write_be64(uint8_t* buf, uint64_t val) {
    buf[0] = static_cast<uint8_t>((val >> 56) & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 48) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 40) & 0xFF);
    buf[3] = static_cast<uint8_t>((val >> 32) & 0xFF);
    buf[4] = static_cast<uint8_t>((val >> 24) & 0xFF);
    buf[5] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[6] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[7] = static_cast<uint8_t>(val & 0xFF);
}

bool set_socket_timeout(int sockfd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return false;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return false;
    }
    return true;
}

bool read_exact(int sockfd, uint8_t* buffer, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t bytes = read(sockfd, buffer + total, n - total);
        if (bytes <= 0) {
            return false;  // Error or EOF or timeout
        }
        total += static_cast<size_t>(bytes);
    }
    return true;
}

bool write_exact(int sockfd, const uint8_t* buffer, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t bytes = write(sockfd, buffer + total, n - total);
        if (bytes <= 0) {
            return false;  // Error or broken pipe
        }
        total += static_cast<size_t>(bytes);
    }
    return true;
}

std::optional<secure::SecureBuffer> read_frame(int sockfd) {
    // Read 4-byte length prefix
    uint8_t len_buf[secure::LENGTH_PREFIX_SIZE];
    if (!read_exact(sockfd, len_buf, secure::LENGTH_PREFIX_SIZE)) {
        return std::nullopt;
    }
    
    uint32_t length = read_be32(len_buf);
    
    // Validate length - prevent memory exhaustion
    if (length == 0 || length > secure::MAX_MESSAGE_SIZE) {
        return std::nullopt;
    }
    
    // Read payload
    secure::SecureBuffer payload(length);
    if (!read_exact(sockfd, payload.data(), length)) {
        return std::nullopt;
    }
    
    return payload;
}

bool write_frame(int sockfd, const uint8_t* data, size_t len) {
    if (len > secure::MAX_MESSAGE_SIZE) {
        return false;
    }
    
    // Write 4-byte length prefix
    uint8_t len_buf[secure::LENGTH_PREFIX_SIZE];
    write_be32(len_buf, static_cast<uint32_t>(len));
    
    if (!write_exact(sockfd, len_buf, secure::LENGTH_PREFIX_SIZE)) {
        return false;
    }
    
    return write_exact(sockfd, data, len);
}

bool write_frame(int sockfd, const secure::SecureBuffer& data) {
    return write_frame(sockfd, data.data(), data.size());
}

} // namespace protocol

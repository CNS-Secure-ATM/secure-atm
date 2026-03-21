cmake_minimum_required(VERSION 3.10)
project(SecureATM VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Security-focused compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wformat=2 -Wformat-security")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

# Find OpenSSL
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${OPENSSL_INCLUDE_DIR})

# Common library sources
set(COMMON_SOURCES
    src/crypto/random.cpp
    src/crypto/keys.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/hmac.cpp
    src/protocol/framing.cpp
    src/protocol/session.cpp
    src/validator/validator.cpp
)

# Build common static library
add_library(common STATIC ${COMMON_SOURCES})
target_link_libraries(common ${OPENSSL_LIBRARIES} Threads::Threads)

# Bank executable
add_executable(bank src/bank/main.cpp)
target_link_libraries(bank common ${OPENSSL_LIBRARIES} Threads::Threads)

# ATM executable  
add_executable(atm src/atm/main.cpp)
target_link_libraries(atm common ${OPENSSL_LIBRARIES} Threads::Threads)

# ============================================================================
# Tests
# ============================================================================
enable_testing()

# Test executables
add_executable(test_validator tests/test_validator.cpp)
target_link_libraries(test_validator common ${OPENSSL_LIBRARIES})

add_executable(test_crypto tests/test_crypto.cpp)
target_link_libraries(test_crypto common ${OPENSSL_LIBRARIES})

add_executable(test_protocol tests/test_protocol.cpp)
target_link_libraries(test_protocol common ${OPENSSL_LIBRARIES})

# DoS
add_executable(dos_attack tests/dos_attack.cpp)

# Register tests with CTest
add_test(NAME validator_tests COMMAND test_validator)
add_test(NAME crypto_tests COMMAND test_crypto)
add_test(NAME protocol_tests COMMAND test_protocol)

# Integration test (runs from build directory)
add_test(NAME integration_tests 
         COMMAND ${CMAKE_COMMAND} -E env bash ${CMAKE_SOURCE_DIR}/tests/test_integration.sh
         WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

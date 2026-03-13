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

# Bank executable
add_executable(bank src/bank/main.cpp)
target_link_libraries(bank ${OPENSSL_LIBRARIES} Threads::Threads)

# ATM executable  
add_executable(atm src/atm/main.cpp)
target_link_libraries(atm ${OPENSSL_LIBRARIES} Threads::Threads)

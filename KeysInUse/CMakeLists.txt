cmake_minimum_required(VERSION 3.13.0)

# Standalone keysinuse library
project(keysinuse)

set(DEFAULT_BUILD_TYPE "Release")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_library(keysinuse SHARED ./keysinuse.c)

if (KEYSINUSE_LOG_SYSLOG)
    target_compile_definitions(keysinuse PRIVATE KEYSINUSE_LOG_SYSLOG)
endif()

target_compile_definitions(keysinuse PRIVATE KEYSINUSE_STANDALONE)
target_include_directories(keysinuse PUBLIC ../ScosslCommon/inc)
target_link_libraries(keysinuse PUBLIC ${OPENSSL_CRYPTO_LIBRARY})
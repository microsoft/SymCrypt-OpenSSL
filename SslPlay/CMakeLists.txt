cmake_minimum_required(VERSION 2.8)

project(SslPlay)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

add_executable (SslPlay
    SslPlay.cpp
)

target_link_libraries(SslPlay LINK_PUBLIC symcryptengine symcrypt ${OPENSSL_CRYPTO_LIBRARY})
#target_link_libraries(SslPlay ${OPENSSL_CRYPTO_LIBRARY})

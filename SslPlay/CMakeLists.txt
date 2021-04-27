cmake_minimum_required(VERSION 2.8)

project(SslPlay)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable (SslPlay
    SslPlay.cpp
)

target_link_directories(SslPlay PUBLIC ${CMAKE_BINARY_DIR} ${CMAKE_INSTALL_LIBDIR})
target_include_directories(SslPlay PUBLIC ${CMAKE_SOURCE_DIR}/SymCryptEngine/inc)

target_link_libraries(SslPlay LINK_PUBLIC $<TARGET_FILE:e_symcrypt> ${OPENSSL_CRYPTO_LIBRARY})
#target_link_libraries(SslPlay ${OPENSSL_CRYPTO_LIBRARY})

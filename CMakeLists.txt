cmake_minimum_required(VERSION 2.8)

project(OpenSSL_FIPS)

include_directories(~/SymCrypt/inc)

# add_subdirectory (SymCryptEngine/static)
add_subdirectory (SymCryptEngine/dynamic)
add_subdirectory (SslPlay)



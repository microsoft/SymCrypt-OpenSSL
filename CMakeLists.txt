cmake_minimum_required(VERSION 2.8)

project(OpenSSL_FIPS)

add_subdirectory (SymcryptEngine/static)
add_subdirectory (SymcryptEngine/dynamic)
add_subdirectory (SslPlay)



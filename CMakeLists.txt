cmake_minimum_required(VERSION 3.13.0)

project(SymCrypt-OpenSSL
    VERSION 1.0.0
    DESCRIPTION "The SymCrypt engine for OpenSSL (SCOSSL)"
    HOMEPAGE_URL "https://github.com/microsoft/SymCrypt-OpenSSL")

include_directories(${SYMCRYPT_ROOT_DIR}/inc)

# In Sanitize version, enable sanitizers
if (CMAKE_BUILD_TYPE MATCHES Sanitize)
    add_compile_options(-fsanitize=address)
    add_compile_options(-fsanitize=leak)
    add_compile_options(-fsanitize=undefined)
    add_compile_options(-fno-sanitize-recover=all)
    add_link_options(-fsanitize=address)
    add_link_options(-fsanitize=leak)
    add_link_options(-fsanitize=undefined)
    add_link_options(-fno-sanitize-recover=all)
endif()

if(CMAKE_BUILD_TYPE MATCHES Release)
    message("Release mode")
else()
    message("Debug mode")
    add_compile_options(-DDBG=1)
endif()

add_subdirectory (SymCryptEngine/static)
add_subdirectory (SymCryptEngine/dynamic)
add_subdirectory (SslPlay)

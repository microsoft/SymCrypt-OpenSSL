cmake_minimum_required(VERSION 3.13.0)

project(SymCrypt-OpenSSL
    VERSION 1.9.2
    DESCRIPTION "The SymCrypt engine and provider for OpenSSL (SCOSSL)"
    HOMEPAGE_URL "https://github.com/microsoft/SymCrypt-OpenSSL")

set(SYMCRYPT_MINIMUM_MAJOR "103")
set(SYMCRYPT_MINIMUM_MINOR "6")

find_package(OpenSSL REQUIRED)

if (SYMCRYPT_ROOT_DIR)
    include_directories(${SYMCRYPT_ROOT_DIR}/inc)
else()
    find_package(PkgConfig)
    if (PKG_CONFIG_FOUND)
        pkg_check_modules(SYMCRYPT REQUIRED symcrypt>=${SYMCRYPT_MINIMUM_MAJOR}.${SYMCRYPT_MINIMUM_MINOR})
        message(STATUS "SymCrypt Includes: ${SYMCRYPT_INCLUDE_DIRS}")
        include_directories(${SYMCRYPT_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "Provide symcrypt pkg-config or set SYMCRYPT_ROOT_DIR variable")
    endif()
endif (SYMCRYPT_ROOT_DIR)

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

if (CMAKE_BUILD_TYPE MATCHES Release|RelWithDebInfo)
    message("Release mode")
else()
    message("Debug mode")
    add_compile_options(-DDBG=1)
endif()

add_subdirectory (ScosslCommon)
add_subdirectory (SymCryptEngine/static)
add_subdirectory (SymCryptEngine/dynamic)
add_subdirectory (SslPlay)

if (${OPENSSL_VERSION} VERSION_GREATER_EQUAL 3)
    add_subdirectory (SymCryptProvider)
endif()

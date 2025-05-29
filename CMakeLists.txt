cmake_minimum_required(VERSION 3.13.0)
include(CheckIncludeFile)

project(SymCrypt-OpenSSL
    VERSION 1.10.0
    DESCRIPTION "The SymCrypt engine and provider for OpenSSL (SCOSSL)"
    HOMEPAGE_URL "https://github.com/microsoft/SymCrypt-OpenSSL")

set(SYMCRYPT_MINIMUM_MAJOR "103")
set(SYMCRYPT_MINIMUM_MINOR "6")

find_package(OpenSSL REQUIRED)

if (SYMCRYPT_ROOT_DIR)
    set(SYMCRYPT_FOUND TRUE)
    include_directories(${SYMCRYPT_ROOT_DIR}/inc)
else()
    # Try to load SymCrypt from pkg-config
    find_package(PkgConfig)
    if (PKG_CONFIG_FOUND)
        pkg_check_modules(SYMCRYPT symcrypt>=${SYMCRYPT_MINIMUM_MAJOR}.${SYMCRYPT_MINIMUM_MINOR})

        if (SYMCRYPT_FOUND)
            message(STATUS "SymCrypt Includes: ${SYMCRYPT_INCLUDE_DIRS}")
            include_directories(${SYMCRYPT_INCLUDE_DIRS})
        endif()            
    endif()

    # Try to find installed SymCrypt
    if (NOT SYMCRYPT_FOUND)
        find_file(SYMCRYPT_HEADER "symcrypt.h" PATHS ${CMAKE_SOURCE_DIR})

        # SymCrypt headers required for all projects, including KeysInUse
        if (NOT SYMCRYPT_HEADER)
            message(FATAL_ERROR "SymCrypt header file not found. Please set SYMCRYPT_ROOT_DIR or install SymCrypt headers.")
        endif()
        
        find_library(SYMCRYPT_LIBRARY symcrypt PATHS ${CMAKE_SOURCE_DIR})
        if (SYMCRYPT_LIBRARY)
        set(SYMCRYPT_FOUND TRUE)
            message(STATUS "Found installed SymCrypt library: ${SYMCRYPT_LIBRARY}")
        else()
            message(WARNING "SymCrypt library not found. Only KeysInUse will be built. Please set SYMCRYPT_ROOT_DIR or install SymCrypt library.")
        endif()
    endif()
endif()

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

if (SYMCRYPT_FOUND AND NOT KEYSINUSE_STANDALONE)
    add_subdirectory (ScosslCommon)
    add_subdirectory (SymCryptEngine/static)
    add_subdirectory (SymCryptEngine/dynamic)
    add_subdirectory (test/SslPlay)
    if (${OPENSSL_VERSION} VERSION_GREATER_EQUAL 3)
        add_subdirectory (SymCryptProvider)
    endif()
endif()

# SymCrypt not needed for just building the KeysInUse standalone library and test
add_subdirectory (KeysInUse)
add_subdirectory (test/KeysInUseTest)
cmake_minimum_required(VERSION 2.8)

project(symcrypt_engine_dynamic)

set(DEFAULT_BUILD_TYPE "Release")

include(GNUInstallDirs)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -Wno-unused-parameter")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Define _AMD64_ to set up the correct SymCrypt macros, e.g. SYMCRYPT_CPU_AMD64
add_compile_options(-D_AMD64_)
add_compile_options(-DDBG)
add_compile_options(-O3)

add_library(e_symcrypt SHARED
    ../src/e_symcrypt.c
    ../src/e_symcrypt_ciphers.c
    ../src/e_symcrypt_dh.c
    ../src/e_symcrypt_digests.c
    ../src/e_symcrypt_dsa.c
    ../src/e_symcrypt_ecc.c
    ../src/e_symcrypt_pkey_meths.c
    ../src/e_symcrypt_rand.c
    ../src/e_symcrypt_rsa.c
    ../src/e_symcrypt_rsapss.c
    ../src/e_symcrypt_hkdf.c
    ../src/e_symcrypt_tls1prf.c
    ../src/e_symcrypt_helpers.c
)

set_target_properties(e_symcrypt PROPERTIES PUBLIC_HEADER ../inc/e_symcrypt.h)

# target_link_libraries(symcryptengine ${OPENSSL_CRYPTO_LIBRARY})

target_include_directories(e_symcrypt PUBLIC ../inc)
target_include_directories(e_symcrypt PRIVATE ../src)
target_include_directories (e_symcrypt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# set_target_properties(e_symcrypt PROPERTIES PREFIX "")
set_target_properties(e_symcrypt PROPERTIES OUTPUT_NAME "symcryptengine")

target_link_directories(e_symcrypt PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(e_symcrypt PUBLIC symcrypt)

install(TARGETS e_symcrypt
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


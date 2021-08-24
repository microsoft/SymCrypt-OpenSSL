cmake_minimum_required(VERSION 2.8)

project(sc_ossl_engine_dynamic)

set(DEFAULT_BUILD_TYPE "Release")

include(GNUInstallDirs)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -Wno-unused-parameter")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Define _AMD64_ to set up the correct SymCrypt macros, e.g. SYMCRYPT_CPU_AMD64
add_compile_options(-D_AMD64_)
add_compile_options(-DDBG)
add_compile_options(-O3)

add_library(sc_ossl_dynamic SHARED
    ../src/sc_ossl.c
    ../src/sc_ossl_ciphers.c
    ../src/sc_ossl_dh.c
    ../src/sc_ossl_digests.c
    ../src/sc_ossl_dsa.c
    ../src/sc_ossl_ecc.c
    ../src/sc_ossl_pkey_meths.c
    ../src/sc_ossl_rand.c
    ../src/sc_ossl_rsa.c
    ../src/sc_ossl_rsapss.c
    ../src/sc_ossl_hkdf.c
    ../src/sc_ossl_tls1prf.c
    ../src/sc_ossl_helpers.c
)

set_target_properties(sc_ossl_dynamic PROPERTIES PUBLIC_HEADER ../inc/sc_ossl.h)
# target_link_libraries(sc_ossl_dynamic ${OPENSSL_CRYPTO_LIBRARY})
target_include_directories(sc_ossl_dynamic PUBLIC ../inc)
target_include_directories(sc_ossl_dynamic PRIVATE ../src)
target_include_directories (sc_ossl_dynamic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# set_target_properties(sc_ossl_dynamic PROPERTIES PREFIX "")
set_target_properties(sc_ossl_dynamic PROPERTIES OUTPUT_NAME "symcryptengine")

target_link_directories(sc_ossl_dynamic PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(sc_ossl_dynamic PUBLIC symcrypt)
target_link_libraries(sc_ossl_dynamic PUBLIC crypto)

install(TARGETS sc_ossl_dynamic
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


cmake_minimum_required(VERSION 3.13.0)

project(scossl_engine_static)

set(DEFAULT_BUILD_TYPE "Release")

include(GNUInstallDirs)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -Wno-unused-parameter")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_library(scossl_static STATIC
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

set_target_properties(scossl_static PROPERTIES PUBLIC_HEADER ../inc/sc_ossl.h)
# target_link_libraries(scossl_static ${OPENSSL_CRYPTO_LIBRARY})
target_include_directories(scossl_static PUBLIC ../inc)
target_include_directories(scossl_static PRIVATE ../src)
target_include_directories (scossl_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)


install(TARGETS scossl_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


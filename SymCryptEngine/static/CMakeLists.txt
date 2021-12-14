cmake_minimum_required(VERSION 3.13.0)

project(scossl_engine_static)

set(DEFAULT_BUILD_TYPE "Release")

include(GNUInstallDirs)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -Wno-unused-parameter")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_library(scossl_static STATIC
    ../src/scossl.c
    ../src/scossl_ciphers.c
    ../src/scossl_dh.c
    ../src/scossl_digests.c
    ../src/scossl_dsa.c
    ../src/scossl_ecc.c
    ../src/scossl_pkey_meths.c
    ../src/scossl_rand.c
    ../src/scossl_rsa.c
    ../src/scossl_rsapss.c
    ../src/scossl_hkdf.c
    ../src/scossl_tls1prf.c
    ../src/scossl_helpers.c
)

set_target_properties(scossl_static PROPERTIES PUBLIC_HEADER ../inc/scossl.h)
# target_link_libraries(scossl_static ${OPENSSL_CRYPTO_LIBRARY})
target_include_directories(scossl_static PUBLIC ../inc)
target_include_directories(scossl_static PRIVATE ../src)
target_include_directories (scossl_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)


install(TARGETS scossl_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


cmake_minimum_required(VERSION 3.13.0)

project(scossl_engine_dynamic)

set(DEFAULT_BUILD_TYPE "Release")

include(GNUInstallDirs)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -Wno-unused-parameter")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_library(scossl_dynamic SHARED
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

set_target_properties(scossl_dynamic PROPERTIES PUBLIC_HEADER ../inc/sc_ossl.h)
# target_link_libraries(scossl_dynamic ${OPENSSL_CRYPTO_LIBRARY})
target_include_directories(scossl_dynamic PUBLIC ../inc)
target_include_directories(scossl_dynamic PRIVATE ../src)
target_include_directories (scossl_dynamic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# set_target_properties(scossl_dynamic PROPERTIES PREFIX "")
set_target_properties(scossl_dynamic PROPERTIES OUTPUT_NAME "symcryptengine")

target_link_directories(scossl_dynamic PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(scossl_dynamic PUBLIC symcrypt)
target_link_libraries(scossl_dynamic PUBLIC ${OPENSSL_CRYPTO_LIBRARY})

# Get the OpenSSL engines directory from the host
execute_process(
    COMMAND openssl version -e
    OUTPUT_VARIABLE OPENSSL_ENGINESDIR
)

# Parse the output of the above command to get just the directory
# ENGINESDIR: /usr/lib/engines -> /usr/lib/engines
string(
    REGEX REPLACE "ENGINESDIR: \"(.*)\""
    "\\1"
    OPENSSL_ENGINESDIR # Output
    ${OPENSSL_ENGINESDIR} # Input
)

install(
    TARGETS scossl_dynamic
    LIBRARY DESTINATION ${OPENSSL_ENGINESDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


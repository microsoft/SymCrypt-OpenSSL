cmake_minimum_required(VERSION 3.13.0)

project(scossl_engine_static)

set(DEFAULT_BUILD_TYPE "Release")

include(GNUInstallDirs)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra  -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra  -Wno-deprecated-declarations -Wno-unused-parameter")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(SCOSSL_SOURCES
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
    ../src/scossl_hmac.c
)

if (SCOSSL_SSHKDF)
    list(APPEND SCOSSL_SOURCES ../src/scossl_sshkdf.c)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSCOSSL_SSHKDF")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSCOSSL_SSHKDF")
endif()


add_library(scossl_static STATIC ${SCOSSL_SOURCES})
add_dependencies(scossl_static scossl_common)

set_target_properties(scossl_static PROPERTIES PUBLIC_HEADER ../inc/scossl.h)
# target_link_libraries(scossl_static ${OPENSSL_CRYPTO_LIBRARY})
target_include_directories(scossl_static PUBLIC ../inc)
target_include_directories(scossl_static PRIVATE ../src)
target_include_directories(scossl_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_include_directories(scossl_static PUBLIC ../ScosslCommon/inc)

target_link_libraries(scossl_static PRIVATE scossl_common)

install(TARGETS scossl_static
    EXCLUDE_FROM_ALL
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

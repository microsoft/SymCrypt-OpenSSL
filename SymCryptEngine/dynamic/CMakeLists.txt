cmake_minimum_required(VERSION 3.13.0)

project(scossl_engine_dynamic)

set(DEFAULT_BUILD_TYPE "Release")

include(GNUInstallDirs)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_library(SYMCRYPT_LIBRARY symcrypt PATHS ${CMAKE_SOURCE_DIR})

set(SCOSSL_SOURCES
    ../src/e_scossl.c
    ../src/e_scossl_ciphers.c
    ../src/e_scossl_dh.c
    ../src/e_scossl_digests.c
    ../src/e_scossl_dsa.c
    ../src/e_scossl_ecc.c
    ../src/e_scossl_rand.c
    ../src/e_scossl_rsa.c
    ../src/e_scossl_rsapss.c
    ../src/e_scossl_hkdf.c
    ../src/e_scossl_tls1prf.c
    ../src/e_scossl_hmac.c
)

if (SCOSSL_SSHKDF)
    list(APPEND SCOSSL_SOURCES ../src/e_scossl_sshkdf.c)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSCOSSL_SSHKDF")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSCOSSL_SSHKDF")
endif()

if (${OPENSSL_VERSION} VERSION_EQUAL 1)
    list(APPEND SCOSSL_SOURCES ../src/e_scossl_pkey_meths.c)
endif()

add_library(scossl_dynamic SHARED ${SCOSSL_SOURCES})
add_dependencies(scossl_dynamic scossl_common)

set_target_properties(scossl_dynamic PROPERTIES PUBLIC_HEADER ../inc/e_scossl.h)
# target_link_libraries(scossl_dynamic ${OPENSSL_CRYPTO_LIBRARY})
target_include_directories(scossl_dynamic PUBLIC ../inc)
target_include_directories(scossl_dynamic PRIVATE ../src)
target_include_directories(scossl_dynamic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(scossl_dynamic PUBLIC ../ScosslCommon/inc)

# Remove default "lib" prefix from symcryptengine.so as OpenSSL engine is not a generic Linux .so
set_target_properties(scossl_dynamic PROPERTIES PREFIX "")
set_target_properties(scossl_dynamic PROPERTIES OUTPUT_NAME "symcryptengine")

target_link_libraries(scossl_dynamic PRIVATE scossl_common)
target_link_libraries(scossl_dynamic PUBLIC ${SYMCRYPT_LIBRARY})
target_link_libraries(scossl_dynamic PUBLIC ${OPENSSL_CRYPTO_LIBRARY})

if (NOT DEFINED OPENSSL_ENGINES)
    set(OPENSSL_ENGINES "${CMAKE_INSTALL_LIBDIR}/engines-1.1" CACHE PATH "Path to OpenSSL engines")
endif()

# Install the engine to the OpenSSL engines directory
# NB: this won't work if the distro has a custom engines directory that doesn't match
# the OpenSSL default.
install(
    TARGETS scossl_dynamic
    LIBRARY DESTINATION "${OPENSSL_ENGINES}"
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


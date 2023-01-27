cmake_minimum_required(VERSION 3.13.0)

project(scossl_provider)

set(DEFAULT_BUILD_TYPE "Release")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -Wno-unused-parameter")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/p_scossl_base.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/p_scossl_base.h)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_library(SYMCRYPT_LIBRARY symcrypt PATHS ${CMAKE_SOURCE_DIR})

set(SCOSSL_SOURCES
    ./src/p_scossl_base.c
    ./src/p_scossl_digests.c
)

# if (SCOSSL_SSHKDF)
#     list(APPEND SCOSSL_SOURCES ./src/p_scossl_sshkdf.c)
#     set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSCOSSL_SSHKDF")
#     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSCOSSL_SSHKDF")
# endif()

add_library(scossl_provider SHARED ${SCOSSL_SOURCES})
add_dependencies(scossl_provider scossl_common)

set_target_properties(scossl_provider PROPERTIES PUBLIC_HEADER ./inc/p_scossl_base.h)
target_include_directories(scossl_provider PUBLIC ./inc)
target_include_directories(scossl_provider PRIVATE ./src)
# target_include_directories(scossl_provider PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(scossl_provider PUBLIC ../ScosslCommon/inc)

# Remove default "lib" prefix from symcryptprovider.so as OpenSSL provider is not a generic Linux .so
set_target_properties(scossl_provider PROPERTIES PREFIX "")
set_target_properties(scossl_provider PROPERTIES OUTPUT_NAME "symcryptprovider")

target_link_libraries(scossl_provider PRIVATE scossl_common)
target_link_libraries(scossl_provider PUBLIC ${SYMCRYPT_LIBRARY})
target_link_libraries(scossl_provider PUBLIC ${OPENSSL_CRYPTO_LIBRARY})

# Install the engine to the OpenSSL modules directory
# NB: this won't work if the distro has a custom modules directory that doesn't match
# the OpenSSL default.
install(
    TARGETS scossl_provider
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/ossl-modules"
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
cmake_minimum_required(VERSION 3.13.0)

project(scossl_common_lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wall -Wextra -Wno-unknown-pragmas -Wno-unused-function")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -std=c++1y -Wall -Wextra -Wno-unused-function")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(SCOSSL_SOURCES
    ./src/scossl_helpers.c
    ./src/scossl_aes_aead.c
    ./src/scossl_dh.c
    ./src/scossl_ecc.c
    ./src/scossl_hkdf.c
    ./src/scossl_mac.c
    ./src/scossl_rsa.c
    ./src/scossl_sshkdf.c
    ./src/scossl_tls1prf.c
)

add_library(scossl_common STATIC ${SCOSSL_SOURCES})

target_include_directories(scossl_common PUBLIC ./inc)
target_include_directories(scossl_common PRIVATE ./src)

set_target_properties(scossl_common PROPERTIES OUTPUT_NAME "scosslcommon")
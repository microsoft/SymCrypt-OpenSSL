cmake_minimum_required(VERSION 3.13.0)

project(SslPlay)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable (SslPlay
    SslPlay.cpp
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")

if (SCOSSL_SSHKDF)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSCOSSL_SSHKDF")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSCOSSL_SSHKDF")
endif()


add_dependencies(SslPlay scossl_common)

target_link_directories(SslPlay PUBLIC ${CMAKE_BINARY_DIR} ${CMAKE_INSTALL_LIBDIR})
target_include_directories(SslPlay PUBLIC ${CMAKE_SOURCE_DIR}/SymCryptEngine/inc)
target_include_directories(SslPlay PUBLIC ${CMAKE_SOURCE_DIR}/ScosslCommon/inc)

target_link_libraries(SslPlay PUBLIC scossl_dynamic ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(SslPlay PRIVATE scossl_common)

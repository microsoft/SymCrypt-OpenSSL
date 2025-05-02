cmake_minimum_required(VERSION 3.13.0)

project(KeysInUseTest)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable (KeysInUseTest
    KeysInUseTest.cpp
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

add_dependencies(KeysInUseTest scossl_common)

target_link_directories(KeysInUseTest PUBLIC ${CMAKE_BINARY_DIR} ${CMAKE_INSTALL_LIBDIR})
target_include_directories(KeysInUseTest PUBLIC ${CMAKE_SOURCE_DIR}/SymCryptEngine/inc)
target_include_directories(KeysInUseTest PUBLIC ${CMAKE_SOURCE_DIR}/ScosslCommon/inc)
target_include_directories(KeysInUseTest PUBLIC ${CMAKE_SOURCE_DIR}/SymCryptProvider/src)

target_link_libraries(KeysInUseTest PUBLIC ${OPENSSL_CRYPTO_LIBRARY})
# target_link_libraries(KeysInUseTest PUBLIC keysinuse)
target_link_libraries(KeysInUseTest PUBLIC scossl_provider)
target_link_libraries(KeysInUseTest PRIVATE scossl_common)

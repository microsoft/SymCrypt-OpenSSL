cmake_minimum_required(VERSION 3.13.0)

project(KeysInUseTest)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable (KeysInUseTest
    KeysInUseTest.cpp
)

if (KEYSINUSE_LOG_SYSLOG)
    target_compile_definitions(KeysInUseTest PRIVATE KEYSINUSE_LOG_SYSLOG)
    target_link_libraries(KeysInUseTest PUBLIC ${SYSTEMD_LIBRARY})
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")

target_link_directories(KeysInUseTest PUBLIC ${CMAKE_BINARY_DIR} ${CMAKE_INSTALL_LIBDIR})
target_include_directories(KeysInUseTest PUBLIC ${CMAKE_SOURCE_DIR}/ScosslCommon/inc)
target_include_directories(KeysInUseTest PUBLIC ${CMAKE_SOURCE_DIR}/KeysInUse)

target_link_libraries(KeysInUseTest PUBLIC ${OPENSSL_CRYPTO_LIBRARY})

if (TARGET scossl_provider)
    target_link_libraries(KeysInUseTest PUBLIC scossl_provider)
else()
    target_link_libraries(KeysInUseTest PUBLIC keysinuse)
endif()

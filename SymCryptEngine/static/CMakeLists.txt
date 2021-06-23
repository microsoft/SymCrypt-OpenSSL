cmake_minimum_required(VERSION 2.8)

project(sc_ossl_engine)

set(DEFAULT_BUILD_TYPE "Release")

include(GNUInstallDirs)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -Wno-unused-parameter")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Set CMake variables that subsequent CMake scripts can check against
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

# For now this is just used for separating the output directories
set(SYMCRYPT_TARGET_ENV Linux)

# Define _AMD64_ to set up the correct SymCrypt macros, e.g. SYMCRYPT_CPU_AMD64
add_compile_options(-D_AMD64_)
add_compile_options(-DDBG)
add_compile_options(-O3)
# Enable a baseline of features for the compiler to support everywhere
# Other than for SSSE3 we do not expect the compiler to generate these instructions anywhere other than with intrinsics
#
# We cannot globally enable AVX and later, as we need to keep use of these instructions behind CPU detection, and the
# instructions are definitely useful enough for a smart compiler to use them in C code (i.e. in memcpy)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3 -mxsave -maes -mpclmul -msha -mrdrnd -mrdseed")
set(CMAKE_ASM_FLAGS "-x assembler-with-cpp")


add_library(sc_ossl STATIC
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

set_target_properties(sc_ossl PROPERTIES PUBLIC_HEADER ../inc/sc_ossl.h)
# target_link_libraries(sc_ossl ${OPENSSL_CRYPTO_LIBRARY})
target_include_directories(sc_ossl PUBLIC ../inc)
target_include_directories(sc_ossl PRIVATE ../src)
target_include_directories (sc_ossl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)


install(TARGETS sc_ossl
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


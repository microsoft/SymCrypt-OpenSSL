cmake_minimum_required(VERSION 3.13)
project(EncoderCleanupTest LANGUAGES C)

find_package(OpenSSL 3.5 REQUIRED)
set(SCOSSL_PROVIDER_DIR "" CACHE PATH "Directory containing symcryptprovider.so")
if(NOT EXISTS "${SCOSSL_PROVIDER_DIR}/symcryptprovider.so")
    message(FATAL_ERROR "Set SCOSSL_PROVIDER_DIR to the built provider directory.")
endif()

enable_testing()
add_executable(encoder_cleanup encoder_cleanup.c)
set_target_properties(encoder_cleanup PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)
target_link_libraries(encoder_cleanup PRIVATE OpenSSL::Crypto)
target_compile_options(encoder_cleanup PRIVATE
    -Wall -Wextra -Werror -g -fsanitize=address -fno-omit-frame-pointer)
target_link_options(encoder_cleanup PRIVATE -fsanitize=address)
add_test(NAME encoder_cleanup COMMAND encoder_cleanup "${SCOSSL_PROVIDER_DIR}")
set_tests_properties(encoder_cleanup PROPERTIES
    ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1:fast_unwind_on_malloc=0")

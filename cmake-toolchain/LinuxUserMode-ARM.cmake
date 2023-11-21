# This toolchain file configures CMake options for Linux User Mode ARM compilation with CPU optimizations.
# To use the toolchain file, run cmake .. -DCMAKE_TOOLCHAIN_FILE="cmake-toolchain/LinuxUserMode-ARM.cmake"

# Set CMake variables that subsequent CMake scripts can check against
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ARM)

# Point compiler sysroot to cross compilation toolchain when cross compiling
if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES armv8l|ARM$|ARM32|aarch32 AND NOT SCOSSL_USE_DEFAULT_COMPILER)
    message(STATUS "Using cross compilation toolchain")

    set(TARGET_TRIPLE arm-linux-gnueabihf)

    set(CMAKE_ASM_COMPILER_TARGET ${TARGET_TRIPLE})
    set(CMAKE_C_COMPILER ${TARGET_TRIPLE}-gcc)
    set(CMAKE_C_COMPILER_TARGET ${TARGET_TRIPLE})
    set(CMAKE_CXX_COMPILER ${TARGET_TRIPLE}-g++)
    set(CMAKE_CXX_COMPILER_TARGET ${TARGET_TRIPLE})

    # C/C++ toolchain (installed on Ubuntu using apt-get gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf)
    set(CMAKE_SYSROOT_COMPILE /usr/${TARGET_TRIPLE})

    find_path(CXX_CROSS_INCLUDE_DIR NAMES ${TARGET_TRIPLE} PATHS /usr/${TARGET_TRIPLE}/include/c++/ PATH_SUFFIXES 15 14 13 12 11 10 9 8 7 6 5 NO_DEFAULT_PATH)
    add_compile_options(-I${CXX_CROSS_INCLUDE_DIR}/${TARGET_TRIPLE})
endif()

add_compile_options(-D_ARM_)
add_compile_options(-O3)
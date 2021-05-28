cmake_minimum_required(VERSION 2.8)

project(OpenSSL_FIPS)

include_directories(~/SymCrypt/inc)

# add_compile_options(-fsanitize=address)
# add_compile_options(-fsanitize=leak)
# add_compile_options(-fsanitize=undefined)
# add_compile_options(-fno-sanitize-recover=all)
# add_link_options(-fsanitize=address)
# add_link_options(-fsanitize=leak)
# add_link_options(-fsanitize=undefined)
# add_link_options(-fno-sanitize-recover=all)

add_subdirectory (SymCryptEngine/static)
add_subdirectory (SymCryptEngine/dynamic)
add_subdirectory (SslPlay)



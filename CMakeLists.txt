cmake_minimum_required(VERSION 2.8 FATAL_ERROR)
project(kmsecure)

set(kmsecure_source_files
    main.cpp
    kmsecure.cpp
    kmcrypto/ikmcrypto.cpp
    kmcrypto/blowfish/blowfish.cpp
    kmcrypto/aes/aes.cpp
    kmcrypto/aes/ctaes.c
    )
include_directories(kmcrypto/)
include_directories(kmcrypto/blowfish)
include_directories(kmcrypto/aes)
add_executable(kmsecure ${kmsecure_source_files})

target_link_libraries(kmsecure)

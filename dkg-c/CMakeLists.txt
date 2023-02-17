cmake_minimum_required(VERSION 3.15.3)
set(CMAKE_MESSAGE_LOG_LEVEL debug)
set(PROJECT mpc)

project(${PROJECT})

enable_language(C ASM)
set(EXECUTABLE ${PROJECT_NAME})
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

file(GLOB_RECURSE SOURCES "libs/*.*" "src/*.*")

add_executable(${EXECUTABLE} ${SOURCES} ${INCLUDES})
add_compile_definitions(USE_BIP32_CACHE=0 USE_BIP39_CACHE=0 USE_MONERO=1)

target_include_directories(${EXECUTABLE} PRIVATE
        src/

        libs/crypto
        libs/crypto/aes
        libs/crypto/chacha20poly1305
        libs/crypto/ed25519-donna
        libs/crypto/monero
        libs/crypto/random_gen
        )

target_compile_options(${EXECUTABLE} PRIVATE
        -Wall -g
        -Werror
        -D_POSIX_C_SOURCE=200809L
        $<$<CONFIG:Debug>:-g3>
        )

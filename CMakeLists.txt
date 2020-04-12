cmake_minimum_required(VERSION 3.12)

project(libtpms VERSION 0.8.0 LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include(GNUInstallDirs)
include(TestBigEndian)
include(CheckSymbolExists)

if(APPLE OR MSVC)
    include(ConanAutoSetup)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Options
option(ENABLE_DEBUG "Create a debug build" OFF)
option(WITH_OPENSSL "Use OpenSSL ad main crypto library" OFF)
option(WITH_TPM2 "Build libtpms with TPM2 support (experimental)" OFF)

# Base checks
if(ENABLE_DEBUG)
    set(CMAKE_BUILD_TYPE "Debug")
endif()
message(STATUS "Library is set to build in ${CMAKE_BUILD_TYPE} mode.")

if(WITH_OPENSSL)
    find_package(OpenSSL REQUIRED)
    if(UNIX)
        find_package(Threads REQUIRED)
    endif()
    set(CMAKE_REQUIRED_LIBRARIES crypto)
    check_symbol_exists(AES_set_encrypt_key "openssl/aes.h" HAVE_AES)
    if(NOT HAVE_AES)
        message(FATAL_ERROR "Is openssl-devel/libssl-dev installed?")
    endif()
endif()

if(WITH_TPM2 AND NOT WITH_OPENSSL)
    message(FATAL_ERROR "TPM2 support requires openssl crypto library")
endif()

add_subdirectory(src)
# add_subdirectory(utils)
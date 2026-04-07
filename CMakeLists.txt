# ESPCrypto - https://github.com/ESPToolKit/esp-crypto
# Copyright ESPToolKit
# MIT License

cmake_minimum_required(VERSION 3.12)

set(ESPCRYPTO_SOURCES
    src/esp_crypto/crypto_core.cpp
    src/esp_crypto/crypto_hash_kdf.cpp
    src/esp_crypto/crypto_symmetric.cpp
    src/esp_crypto/crypto_asymmetric.cpp
    src/esp_crypto/crypto_storage.cpp
    src/esp_crypto/crypto_jwt.cpp
)

if(ESP_PLATFORM)
    idf_component_register(
        SRCS ${ESPCRYPTO_SOURCES}
        INCLUDE_DIRS src
        REQUIRES mbedtls nvs_flash esp_timer
    )
    return()
endif()

project(ESPCrypto)

include(CTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(${COVERAGE})
    set(CMAKE_CXX_FLAGS "-fprofile-arcs -ftest-coverage -g -O0")
endif()

include_directories(${CMAKE_CURRENT_LIST_DIR}/src)

if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/test/CMakeLists.txt")
    add_subdirectory(test)
endif()

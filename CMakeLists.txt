cmake_minimum_required(VERSION 3.10)
project(SecureSignService)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)

if(APPLE)
    # Allow manual override: -DHOMEBREW_PATH=/opt/homebrew/opt
    if(NOT DEFINED HOMEBREW_PATH)
        set(HOMEBREW_PATH "/opt/homebrew/opt")
    endif()

    message(STATUS "Building on macOS, using Homebrew path: ${HOMEBREW_PATH}")
    include_directories("${HOMEBREW_PATH}/libsodium/include" "${HOMEBREW_PATH}/secp256k1/include")
    link_directories("${HOMEBREW_PATH}/libsodium/lib" "${HOMEBREW_PATH}/secp256k1/lib")

    set(EXTRA_LIBS sodium secp256k1)
else()
    pkg_check_modules(LIBSODIUM REQUIRED libsodium)
    pkg_check_modules(LIBSECP256K1 REQUIRED libsecp256k1)
    include_directories(${LIBSODIUM_INCLUDE_DIRS} ${LIBSECP256K1_INCLUDE_DIRS})
    link_directories(${LIBSODIUM_LIBRARY_DIRS} ${LIBSECP256K1_LIBRARY_DIRS})
    set(EXTRA_LIBS ${LIBSODIUM_LIBRARIES} ${LIBSECP256K1_LIBRARIES})
endif()

add_executable(secure_sign_service
    src/main.cpp
    src/KeyManager.cpp
    src/CryptoService.cpp
    src/IPCServer.cpp
)

target_link_libraries(secure_sign_service ${EXTRA_LIBS})

add_executable(client client.cpp)
target_link_libraries(client ${EXTRA_LIBS})

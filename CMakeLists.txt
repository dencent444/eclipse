cmake_minimum_required(VERSION 3.22)
project(eclipse_token LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# The current logger, ncurses UI, and developer pipelines use POSIX APIs.
# Fail clearly on unsupported targets instead of silently configuring a
# binary that cannot compile. CPU selection itself belongs to the target C
# compiler; there are no host-specific -march flags in this project.
if(NOT UNIX)
    message(FATAL_ERROR "Eclipse currently requires a POSIX target (Linux, macOS, or BSD).")
endif()
message(STATUS "Eclipse CMake target hint: ${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR}, pointer size ${CMAKE_SIZEOF_VOID_P} bytes")
message(STATUS "CPU architecture is selected from target compiler macros; no host CPU flags are added")

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)
find_package(Curses REQUIRED)
find_package(CURL 7.86 REQUIRED)

add_library(eclipse_core STATIC
    src/core/block/block.c
    src/core/crypto/ml_dsa.c
    src/core/crypto/ml_dsa_math.c
    src/core/encoding/base92.c
    src/core/net/tcp.c
    src/core/net/udp.c
    src/core/net/websocket.c
    src/core/particle/particle.c
    src/core/wallet/keypair.c
    src/core/wallet/recovery.c
    src/core/wallet/wallet.c
    src/core/log.c
)
target_include_directories(eclipse_core PUBLIC src/core)
target_link_libraries(eclipse_core PUBLIC OpenSSL::Crypto Threads::Threads CURL::libcurl)

add_executable(eclipse-cli src/cli/main.c src/cli/pipeline.c src/cli/host_shell.c)
target_include_directories(eclipse-cli PRIVATE ${CURSES_INCLUDE_DIRS})
target_link_libraries(eclipse-cli PRIVATE eclipse_core ${CURSES_LIBRARIES})

include(CTest)
if(BUILD_TESTING)
    math(EXPR ECLIPSE_TEST_POINTER_BITS "${CMAKE_SIZEOF_VOID_P} * 8")
    add_executable(block_header_test tests/serialize_deserialize_test1.c)
    target_link_libraries(block_header_test PRIVATE eclipse_core)
    add_test(NAME block_header_test COMMAND block_header_test)

    add_executable(ml_dsa_test tests/ml_dsa_test.c)
    target_link_libraries(ml_dsa_test PRIVATE eclipse_core)
    add_test(NAME ml_dsa_test COMMAND ml_dsa_test)

    add_executable(ml_dsa_math_test tests/ml_dsa_math_test.c)
    target_link_libraries(ml_dsa_math_test PRIVATE eclipse_core)
    add_test(NAME ml_dsa_math_test COMMAND ml_dsa_math_test)

    add_executable(log_test tests/log_test.c)
    target_link_libraries(log_test PRIVATE eclipse_core)
    add_test(NAME log_test COMMAND log_test)

    add_executable(base92_test tests/base92_test.c)
    target_link_libraries(base92_test PRIVATE eclipse_core)
    add_test(NAME base92_test COMMAND base92_test)

    add_executable(particle_test tests/particle_test.c)
    target_link_libraries(particle_test PRIVATE eclipse_core)
    add_test(NAME particle_test COMMAND particle_test)

    add_executable(wallet_test tests/wallet_test.c)
    target_link_libraries(wallet_test PRIVATE eclipse_core)
    add_test(NAME wallet_test COMMAND wallet_test)

    add_executable(net_test tests/net_test.c)
    target_link_libraries(net_test PRIVATE eclipse_core)
    add_test(NAME net_test COMMAND net_test)

    add_test(NAME cli_test COMMAND ${CMAKE_COMMAND}
        -DCLI=$<TARGET_FILE:eclipse-cli>
        -DTEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -DEXPECTED_POINTER_BITS=${ECLIPSE_TEST_POINTER_BITS}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.cmake)
endif()

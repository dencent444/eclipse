cmake_minimum_required(VERSION 3.22)
project(eclipse_token LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)
find_package(Curses REQUIRED)

add_library(eclipse_core STATIC
    src/core/block/block.c
    src/core/crypto/ml_dsa.c
    src/core/crypto/ml_dsa_math.c
    src/core/encoding/base92.c
    src/core/wallet/keypair.c
    src/core/wallet/wallet.c
    src/core/log.c
)
target_include_directories(eclipse_core PUBLIC src/core)
target_link_libraries(eclipse_core PUBLIC OpenSSL::Crypto Threads::Threads)

add_executable(eclipse-cli src/cli/main.c)
target_include_directories(eclipse-cli PRIVATE ${CURSES_INCLUDE_DIRS})
target_link_libraries(eclipse-cli PRIVATE eclipse_core ${CURSES_LIBRARIES})

include(CTest)
if(BUILD_TESTING)
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

    add_executable(wallet_test tests/wallet_test.c)
    target_link_libraries(wallet_test PRIVATE eclipse_core)
    add_test(NAME wallet_test COMMAND wallet_test)

    add_test(NAME cli_test COMMAND ${CMAKE_COMMAND}
        -DCLI=$<TARGET_FILE:eclipse-cli>
        -DTEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.cmake)
endif()

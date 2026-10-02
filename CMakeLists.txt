cmake_minimum_required(VERSION 3.22)
project(eclipse_token LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

add_library(eclipse_core STATIC
    src/core/block/block.c
    src/core/crypto/ml_dsa.c
    src/core/crypto/ml_dsa_math.c
    src/core/log.c
)
target_include_directories(eclipse_core PUBLIC src/core)
target_link_libraries(eclipse_core PUBLIC OpenSSL::Crypto Threads::Threads)

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
endif()

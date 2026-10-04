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
    src/core/block/chain.c
    src/core/block/chain_store.c
    src/core/block/miner.c
    src/core/crypto/ml_dsa.c
    src/core/crypto/ml_dsa_math.c
    src/core/encoding/base92.c
    src/core/net/tcp.c
    src/core/net/udp.c
    src/core/net/websocket.c
    src/core/particle/particle.c
    src/core/tx/tx.c
    src/core/tx/utxo.c
    src/core/tx/mempool.c
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

# Standalone node with separate Unix control and developer TCP P2P interfaces.
add_executable(eclipse-node src/node/main.c src/node/p2p.c src/node/tor_onion.c)
target_link_libraries(eclipse-node PRIVATE eclipse_core)

# The shielded verifier is an opt-in, verifier-only Rust/C boundary. EBL1
# blocks do not carry ESX1 yet, so building this does not activate new rules.
option(ECLIPSE_BUILD_SHIELDED "Build experimental Orchard verifier bridge" OFF)
if(ECLIPSE_BUILD_SHIELDED)
    find_program(ECLIPSE_CARGO_EXECUTABLE cargo REQUIRED)
    set(ECLIPSE_SHIELDED_CARGO_TARGET_DIR
        "${CMAKE_BINARY_DIR}/rust-shielded" CACHE PATH
        "Cargo target directory for the experimental verifier")
    set(ECLIPSE_SHIELDED_RUST_TARGET "" CACHE STRING
        "Rust target triple when cross compiling the experimental verifier")
    if(CMAKE_CROSSCOMPILING AND ECLIPSE_SHIELDED_RUST_TARGET STREQUAL "")
        message(FATAL_ERROR "Set ECLIPSE_SHIELDED_RUST_TARGET to the C toolchain's Rust target triple")
    endif()
    set(ECLIPSE_SHIELDED_CARGO_TARGET_ARGS)
    set(ECLIPSE_SHIELDED_RUST_PROFILE_DIR "${ECLIPSE_SHIELDED_CARGO_TARGET_DIR}")
    if(NOT ECLIPSE_SHIELDED_RUST_TARGET STREQUAL "")
        list(APPEND ECLIPSE_SHIELDED_CARGO_TARGET_ARGS
            --target "${ECLIPSE_SHIELDED_RUST_TARGET}")
        set(ECLIPSE_SHIELDED_RUST_PROFILE_DIR
            "${ECLIPSE_SHIELDED_CARGO_TARGET_DIR}/${ECLIPSE_SHIELDED_RUST_TARGET}")
    endif()
    set(ECLIPSE_SHIELDED_RUST_LIB
        "${ECLIPSE_SHIELDED_RUST_PROFILE_DIR}/debug/libeclipse_shielded.a")
    add_custom_command(OUTPUT "${ECLIPSE_SHIELDED_RUST_LIB}"
        COMMAND "${CMAKE_COMMAND}" -E env
            "CARGO_TARGET_DIR=${ECLIPSE_SHIELDED_CARGO_TARGET_DIR}"
            "${ECLIPSE_CARGO_EXECUTABLE}" build --locked --lib
            ${ECLIPSE_SHIELDED_CARGO_TARGET_ARGS}
            --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/rust/shielded/Cargo.toml"
        DEPENDS
            rust/shielded/Cargo.toml rust/shielded/Cargo.lock
            rust/shielded/src/lib.rs rust/shielded/src/tx.rs
            rust/shielded/src/ledger.rs rust/shielded/src/ffi.rs
        VERBATIM)
    add_custom_target(eclipse_shielded_cargo DEPENDS "${ECLIPSE_SHIELDED_RUST_LIB}")
    add_library(eclipse_shielded_rust STATIC IMPORTED GLOBAL)
    set_target_properties(eclipse_shielded_rust PROPERTIES
        IMPORTED_LOCATION "${ECLIPSE_SHIELDED_RUST_LIB}")
    add_dependencies(eclipse_shielded_rust eclipse_shielded_cargo)
    add_library(eclipse_shielded_bridge STATIC src/core/shielded/shielded.c)
    target_link_libraries(eclipse_shielded_bridge PUBLIC
        eclipse_shielded_rust eclipse_core Threads::Threads ${CMAKE_DL_LIBS} m)
endif()

# Explicit opt-in for Clang/libFuzzer. Configure a separate build tree with
# -fsanitize=fuzzer-no-link,address,undefined so ordinary binaries still link.
option(ECLIPSE_BUILD_FUZZ "Build libFuzzer parser harness" OFF)
if(ECLIPSE_BUILD_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "ECLIPSE_BUILD_FUZZ requires Clang/libFuzzer")
    endif()
    add_executable(eclipse-fuzz-decode tests/fuzz_decode.c)
    target_link_libraries(eclipse-fuzz-decode PRIVATE eclipse_core)
    target_link_options(eclipse-fuzz-decode PRIVATE -fsanitize=fuzzer)
endif()

include(CTest)
if(BUILD_TESTING)
    if(ECLIPSE_BUILD_SHIELDED)
        add_executable(shielded_bridge_test tests/shielded_bridge_test.c)
        target_link_libraries(shielded_bridge_test PRIVATE eclipse_shielded_bridge)
        add_test(NAME shielded_bridge_test COMMAND shielded_bridge_test
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/esx1_reward.bin")
    endif()
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

    add_executable(tx_test tests/tx_test.c)
    target_link_libraries(tx_test PRIVATE eclipse_core)
    add_test(NAME tx_test COMMAND tx_test)

    add_executable(utxo_index_test tests/utxo_index_test.c)
    target_link_libraries(utxo_index_test PRIVATE eclipse_core)
    add_test(NAME utxo_index_test COMMAND utxo_index_test)

    add_executable(chain_test tests/chain_test.c)
    target_link_libraries(chain_test PRIVATE eclipse_core)
    add_test(NAME chain_test COMMAND chain_test)

    add_executable(chain_storage_mempool_test tests/chain_storage_mempool_test.c)
    target_link_libraries(chain_storage_mempool_test PRIVATE eclipse_core)
    add_test(NAME chain_storage_mempool_test COMMAND chain_storage_mempool_test)

    add_test(NAME cli_test COMMAND ${CMAKE_COMMAND}
        -DCLI=$<TARGET_FILE:eclipse-cli>
        -DTEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -DEXPECTED_POINTER_BITS=${ECLIPSE_TEST_POINTER_BITS}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.cmake)

    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_executable(node_tx_fixture tests/node_tx_fixture.c)
        target_link_libraries(node_tx_fixture PRIVATE eclipse_core)
        add_test(NAME node_integration_test COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/node_integration.py
            $<TARGET_FILE:eclipse-node> $<TARGET_FILE:node_tx_fixture>)
        add_test(NAME p2p_integration_test COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/p2p_integration.py
            $<TARGET_FILE:eclipse-node> $<TARGET_FILE:node_tx_fixture>)
        add_test(NAME p2p_socks_test COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/p2p_socks_test.py
            $<TARGET_FILE:eclipse-node> $<TARGET_FILE:node_tx_fixture>)
        add_test(NAME p2p_deep_fork_test COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/p2p_deep_fork_test.py
            $<TARGET_FILE:eclipse-node> $<TARGET_FILE:node_tx_fixture>)
        add_test(NAME tor_onion_integration_test COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/tor_onion_integration.py
            $<TARGET_FILE:eclipse-node>)
    endif()
endif()

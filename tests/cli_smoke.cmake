# Exercise commands as subprocesses so stdout, stderr logging, and // pipes
# are checked the same way a developer uses the compiled executable.
if(NOT DEFINED CLI OR NOT DEFINED TEST_BINARY_DIR OR
   NOT DEFINED EXPECTED_POINTER_BITS)
    message(FATAL_ERROR "CLI, TEST_BINARY_DIR and EXPECTED_POINTER_BITS are required")
endif()

execute_process(
    COMMAND "${CLI}" build-info
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR
   NOT OUTPUT MATCHES "^os=[^\n]+\narchitecture=[^\n]+\npointer_bits=${EXPECTED_POINTER_BITS}\nbyte_order=(little|big|unknown)$")
    message(FATAL_ERROR "compiled target information is wrong: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

string(REPEAT "0" 64 ZERO_HASH)
set(EXPECTED_WIRE "000000010000000000000002000000030000000000000004${ZERO_HASH}${ZERO_HASH}")

# Positional mode is intentionally free of ncurses control characters so
# developers can feed the result into other tools.
execute_process(
    COMMAND "${CLI}" serialize 1 2 3 4 "${ZERO_HASH}" "${ZERO_HASH}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL EXPECTED_WIRE)
    message(FATAL_ERROR "positional serialization failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

set(CALL "serialize(1, 2, 3, 4, ${ZERO_HASH}, ${ZERO_HASH})")
execute_process(
    COMMAND "${CLI}" "${CALL}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL EXPECTED_WIRE)
    message(FATAL_ERROR "parenthesized serialization failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

execute_process(
    COMMAND "${CLI}" deserialize "${EXPECTED_WIRE}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR)
if(NOT RESULT EQUAL 0 OR
   NOT OUTPUT MATCHES "version=1\ntimestamp=2\ndifficulty=3\nnonce=4\n" OR
   NOT OUTPUT MATCHES "prev_block_hash=${ZERO_HASH}\nmerkle_root=${ZERO_HASH}\n")
    message(FATAL_ERROR "deserialization failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

execute_process(
    COMMAND "${CLI}" deserialize abc
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR)
if(NOT RESULT EQUAL 2 OR NOT OUTPUT STREQUAL "")
    message(FATAL_ERROR "invalid header was accepted: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

execute_process(
    COMMAND "${CLI}" math mod -1
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "8380416")
    message(FATAL_ERROR "modular arithmetic failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

execute_process(
    COMMAND "${CLI}" ml-dsa self-test 44 "development message" eclipse-cli
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "ML-DSA-44: valid")
    message(FATAL_ERROR "ML-DSA self-test failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

set(LOG_FILE "${TEST_BINARY_DIR}/cli-smoke.log")
execute_process(
    COMMAND "${CLI}" --log-level 5 --log-file "${LOG_FILE}"
            serialize 1 2 3 4 "${ZERO_HASH}" "${ZERO_HASH}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR)
if(NOT RESULT EQUAL 0)
    message(FATAL_ERROR "CLI logging command failed: ${RESULT}\n${ERROR}")
endif()
file(READ "${LOG_FILE}" LOG_CONTENT)
if(NOT LOG_CONTENT MATCHES "eclipse_block_header_serialize: block header serialized" OR
   LOG_CONTENT MATCHES "${ZERO_HASH}")
    message(FATAL_ERROR "CLI log is missing the serializer event or contains input data")
endif()

set(RECEIVE "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
set(SPEND "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
set(RANDOM "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
set(COMMITMENT "cbadd903974ab7eb94d7a9790cb606c02169be1f11eeda6c1f839a361c8cc702")
execute_process(
    COMMAND "${CLI}" particle commit 0x0102030405060708 "${RECEIVE}" "${SPEND}" "${RANDOM}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "commitment=${COMMITMENT}")
    message(FATAL_ERROR "particle commitment vector failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" particle verify 0x0102030405060708 "${RECEIVE}" "${SPEND}" "${RANDOM}" "${COMMITMENT}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "valid=true")
    message(FATAL_ERROR "particle verification failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" particle verify 3 "${RECEIVE}" "${SPEND}" "${RANDOM}" "${COMMITMENT}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "valid=false")
    message(FATAL_ERROR "particle mismatch was accepted: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" particle create 9 "${RECEIVE}" "${SPEND}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT MATCHES "amount=9\nreceive_material=${RECEIVE}\nspend_authority=${SPEND}\nrandomness=[0-9a-f]+\ncommitment=[0-9a-f]+\n")
    message(FATAL_ERROR "particle creation failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

execute_process(
    COMMAND "${CLI}" base92 encode 68656c6c6f20776f726c64
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "Fc_$aOTdKnsM*k")
    message(FATAL_ERROR "Base92 encode failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" base92 decode "Fc_$aOTdKnsM*k"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "68656c6c6f20776f726c64")
    message(FATAL_ERROR "Base92 decode failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" pipe "base92 encode 68656c6c6f20776f726c64 // base92 decode -"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "68656c6c6f20776f726c64")
    message(FATAL_ERROR "Base92 data pipe failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

execute_process(
    COMMAND "${CLI}" keypair generate 44
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT MATCHES "^[0-9a-f]+$")
    message(FATAL_ERROR "standalone keypair failed: ${RESULT}\n${ERROR}")
endif()

execute_process(
    COMMAND "${CLI}" wallet create 44
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE ROOT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR ROOT STREQUAL "")
    message(FATAL_ERROR "wallet creation failed: ${RESULT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" wallet domain "${ROOT}" receive
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE DOMAIN ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR DOMAIN STREQUAL "")
    message(FATAL_ERROR "receive-domain export failed: ${RESULT}\n${ERROR}")
endif()
string(FIND "${ERROR}" "${ROOT}" ROOT_LOG_POS)
if(NOT ROOT_LOG_POS EQUAL -1)
    message(FATAL_ERROR "wallet root appeared in CLI diagnostics")
endif()
execute_process(
    COMMAND "${CLI}" wallet role-public "${DOMAIN}" receive 0
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE PUBLIC_PACKET ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR PUBLIC_PACKET STREQUAL "")
    message(FATAL_ERROR "receive-domain public key failed: ${RESULT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" pipe "wallet create 44 // wallet domain - receive // wallet role-public - receive 0 // wallet public-decode -"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT MATCHES "scheme=44\nlength=1312\npublic_key=[0-9a-f]+")
    message(FATAL_ERROR "wallet domain pipe failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" wallet public-decode "${PUBLIC_PACKET}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT MATCHES "scheme=44\nlength=1312\npublic_key=[0-9a-f]+\n")
    message(FATAL_ERROR "wallet public packet decode failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" wallet verify "${ROOT}" receive 0
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "valid=true")
    message(FATAL_ERROR "wallet child binding failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

set(PIPELINE "serialize(1,2,3,4,${ZERO_HASH},${ZERO_HASH}) // deserialize // !grep version")
execute_process(
    COMMAND "${CLI}" pipe "${PIPELINE}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "version=1")
    message(FATAL_ERROR "explicit pipeline failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" "${PIPELINE}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "version=1")
    message(FATAL_ERROR "direct pipeline failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
set(SHELL_INPUT "${TEST_BINARY_DIR}/cli-shell-input.txt")
file(WRITE "${SHELL_INPUT}" "${PIPELINE}\nexit\n")
execute_process(
    COMMAND "${CLI}" shell INPUT_FILE "${SHELL_INPUT}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "version=1")
    message(FATAL_ERROR "developer shell failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()
execute_process(
    COMMAND "${CLI}" pipe "deserialize //"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR)
if(NOT RESULT EQUAL 2)
    message(FATAL_ERROR "malformed pipeline was accepted: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

# A raw line read by Eclipse is unaffected by the syntax rules of the shell
# that launched the already-compiled binary.
set(RAW_PIPE_INPUT "${TEST_BINARY_DIR}/cli-raw-pipe.txt")
file(WRITE "${RAW_PIPE_INPUT}" "math mod -1 // !cat\n")
execute_process(
    COMMAND "${CLI}" pipe - INPUT_FILE "${RAW_PIPE_INPUT}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RESULT EQUAL 0 OR NOT OUTPUT STREQUAL "8380416")
    message(FATAL_ERROR "stdin pipeline failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
endif()

# The parent here is CMake, so detection uses the SHELL hint. Check that the
# resulting guidance follows the runtime profile without another build.
foreach(PROFILE IN ITEMS bash zsh fish pwsh sh)
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env "SHELL=/bin/${PROFILE}" "${CLI}" shell-info
        RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR)
    if(PROFILE STREQUAL "pwsh")
        set(EXPECTED_PROFILE "PowerShell")
    elseif(PROFILE STREQUAL "sh")
        set(EXPECTED_PROFILE "POSIX shell")
    else()
        set(EXPECTED_PROFILE "${PROFILE}")
    endif()
    if(NOT RESULT EQUAL 0 OR NOT OUTPUT MATCHES "Detected outer shell: ${EXPECTED_PROFILE}")
        message(FATAL_ERROR "shell profile ${PROFILE} failed: ${RESULT}\n${OUTPUT}\n${ERROR}")
    endif()
endforeach()

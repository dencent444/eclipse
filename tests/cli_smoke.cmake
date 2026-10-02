if(NOT DEFINED CLI OR NOT DEFINED TEST_BINARY_DIR)
    message(FATAL_ERROR "CLI and TEST_BINARY_DIR are required")
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

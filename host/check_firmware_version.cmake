# Regression for configurable CTAP getInfo firmware version.
#
# 1. Compile a probe that includes fido/omk_ctap.h with the configured
#    -DOMK_FIRMWARE_VERSION and assert the alias expands to it.  -Werror
#    catches a clashing #define in the header.
# 2. Preprocess omk_ctap.c and verify key 14 is followed by the configured
#    numeric value, i.e. the setting actually feeds getInfo.

cmake_minimum_required(VERSION 3.25)

foreach(required IN ITEMS OMK_C_COMPILER OMK_SOURCE_DIR OMK_EXPECTED_VERSION
                          OMK_WORK_DIR)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "firmware version probe: ${required} is not set")
    endif()
endforeach()

if(NOT OMK_EXPECTED_VERSION MATCHES "^[0-9]+$")
    message(FATAL_ERROR
        "firmware version probe: expected decimal version, got "
        "'${OMK_EXPECTED_VERSION}'")
endif()

if(NOT OMK_WORK_DIR MATCHES "/firmware-version-probe/?$")
    message(FATAL_ERROR
        "firmware version probe: refusing unsafe scratch directory "
        "'${OMK_WORK_DIR}'")
endif()

set(src "${OMK_SOURCE_DIR}/src")
if(NOT EXISTS "${src}/fido/omk_ctap.c")
    message(FATAL_ERROR "firmware version probe: no source tree at '${src}'")
endif()

file(REMOVE_RECURSE "${OMK_WORK_DIR}")
file(MAKE_DIRECTORY "${OMK_WORK_DIR}")

set(probe "${OMK_WORK_DIR}/version_probe.c")
set(probe_contents [=[
#include "fido/omk_ctap.h"

#if !defined(OMK_CTAP_FIRMWARE_VERSION)
#error "OMK_CTAP_FIRMWARE_VERSION is not defined"
#endif
#if OMK_CTAP_FIRMWARE_VERSION != OMK_FIRMWARE_VERSION
#error "getInfo version alias does not track OMK_FIRMWARE_VERSION"
#endif
#if OMK_FIRMWARE_VERSION != EXPECTED_VERSION
#error "OMK_FIRMWARE_VERSION did not expand to the configured value"
#endif

int main(void) {
    return 0;
}
]=])
# Substitute the expected value without going through configure_file.
string(REPLACE "EXPECTED_VERSION" "${OMK_EXPECTED_VERSION}" probe_contents
    "${probe_contents}")
file(WRITE "${probe}" "${probe_contents}")

execute_process(
    COMMAND "${OMK_C_COMPILER}"
            -std=c17 -Wall -Wextra -Werror
            "-DOMK_FIRMWARE_VERSION=${OMK_EXPECTED_VERSION}"
            "-I${src}"
            "${probe}" -o "${OMK_WORK_DIR}/version_probe"
    RESULT_VARIABLE compile_rc
    OUTPUT_VARIABLE compile_out
    ERROR_VARIABLE compile_err)
if(NOT compile_rc EQUAL 0)
    message(FATAL_ERROR
        "firmware version probe: compile failed (${compile_rc}):\n"
        "${compile_out}${compile_err}")
endif()

execute_process(
    COMMAND "${OMK_C_COMPILER}"
            -std=c17
            "-DOMK_FIRMWARE_VERSION=${OMK_EXPECTED_VERSION}"
            "-I${src}"
            -E "${src}/fido/omk_ctap.c"
    RESULT_VARIABLE pp_rc
    OUTPUT_VARIABLE preprocessed
    ERROR_VARIABLE pp_err)
if(NOT pp_rc EQUAL 0)
    message(FATAL_ERROR
        "firmware version probe: preprocessing omk_ctap.c failed (${pp_rc}):\n"
        "${pp_err}")
endif()

string(REGEX REPLACE "[ \t\r\n]+" " " compact "${preprocessed}")
string(FIND "${compact}"
    "omk_cbor_put_uint(&e, 14); omk_cbor_put_uint(&e, ${OMK_EXPECTED_VERSION});"
    version_index)
if(version_index EQUAL -1)
    message(FATAL_ERROR
        "firmware version probe: getInfo key 14 is not encoded from "
        "OMK_FIRMWARE_VERSION=${OMK_EXPECTED_VERSION}")
endif()

message(STATUS
    "firmware version probe: getInfo key 14 encodes ${OMK_EXPECTED_VERSION}")

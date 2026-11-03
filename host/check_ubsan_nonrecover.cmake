# Regression: UBSan must be non-recoverable at compile time.  Compile a
# deliberate signed-overflow probe with the same flags the core and host tests
# use; if -fno-sanitize-recover=all was dropped, the probe exits 0 and this
# test fails.

cmake_minimum_required(VERSION 3.25)

foreach(required IN ITEMS OMK_C_COMPILER OMK_SAN_FLAGS OMK_SAN_LINK_FLAGS
                          OMK_WORK_DIR)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "ubsan probe: ${required} is not set")
    endif()
endforeach()

if(NOT OMK_WORK_DIR MATCHES "/ubsan-probe/?$")
    message(FATAL_ERROR
        "ubsan probe: refusing unsafe scratch directory '${OMK_WORK_DIR}'")
endif()

file(REMOVE_RECURSE "${OMK_WORK_DIR}")
file(MAKE_DIRECTORY "${OMK_WORK_DIR}")

set(probe "${OMK_WORK_DIR}/ubsan_probe.c")
file(WRITE "${probe}" [=[
#include <limits.h>

int main(void) {
    volatile int value = INT_MAX;
    value = value + 1; /* signed overflow: UBSan must abort, not recover */
    return value == 0 ? 0 : 0;
}
]=])

string(REPLACE "|" ";" san_flags "${OMK_SAN_FLAGS}")
string(REPLACE "|" ";" san_link_flags "${OMK_SAN_LINK_FLAGS}")
set(exe "${OMK_WORK_DIR}/ubsan_probe")
execute_process(
    COMMAND "${OMK_C_COMPILER}" ${san_flags} "${probe}" -o "${exe}"
            ${san_link_flags}
    RESULT_VARIABLE compile_rc
    OUTPUT_VARIABLE compile_out
    ERROR_VARIABLE compile_err)
if(NOT compile_rc EQUAL 0)
    message(FATAL_ERROR
        "ubsan probe: compile failed (${compile_rc}):\n${compile_out}${compile_err}")
endif()

# halt_on_error=0 isolates the compile-time behaviour: a recoverable build must
# still return success here.
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
            "UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0"
            "ASAN_OPTIONS=detect_leaks=0"
            "${exe}"
    RESULT_VARIABLE run_rc
    OUTPUT_VARIABLE run_out
    ERROR_VARIABLE run_err)
if(run_rc EQUAL 0)
    message(FATAL_ERROR
        "ubsan probe: signed overflow was allowed to recover; missing "
        "-fno-sanitize-recover=all (flags: ${OMK_SAN_FLAGS})")
endif()

message(STATUS
    "ubsan probe: non-recoverable undefined behaviour exited ${run_rc}")

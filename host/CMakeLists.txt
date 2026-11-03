# Host-side tests and fuzz targets.
#
# Everything under host/ must stay free of pico-sdk includes so it can run on
# the developer machine and in CI without an embedded toolchain.

set(OMK_WARNINGS -Wall -Wextra -Werror)
# UBSan is non-recoverable at compile time, and the CTest environment repeats
# halt_on_error so a build with stale objects or a different runtime still
# cannot exit green on undefined behaviour.
set(OMK_SAN_FLAGS
    -fsanitize=address,undefined
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer)
set(OMK_SAN_LINK_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all)
set(OMK_TEST_ENV
    "UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1")

omk_enable_reproducible_prefix_maps()

# Protocol/crypto core shared with the firmware build.
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/core-sources.cmake)
list(LENGTH OMK_CORE_SOURCES OMK_CORE_SOURCE_COUNT)

add_library(omk_core STATIC ${OMK_CORE_SOURCES})
target_include_directories(omk_core PUBLIC ../src)
target_compile_definitions(omk_core PRIVATE
    OMK_FIRMWARE_VERSION=${OMK_FIRMWARE_VERSION})
target_compile_options(omk_core PRIVATE -std=c17 ${OMK_WARNINGS})
if(OMK_SANITIZE)
    target_compile_options(omk_core PRIVATE ${OMK_SAN_FLAGS})
endif()

function(omk_host_test name)
    add_executable(${name} tests/${name}.c)
    target_link_libraries(${name} PRIVATE omk_core)
    target_compile_options(${name} PRIVATE -std=c17 ${OMK_WARNINGS})
    if(OMK_SANITIZE)
        target_compile_options(${name} PRIVATE ${OMK_SAN_FLAGS})
        target_link_options(${name} PRIVATE ${OMK_SAN_LINK_FLAGS})
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES ENVIRONMENT "${OMK_TEST_ENV}")
endfunction()

omk_host_test(test_build_smoke)
omk_host_test(test_crypto)
omk_host_test(test_cbor)
omk_host_test(test_ctaphid)
omk_host_test(test_p256)
omk_host_test(test_crypto_ed25519)
omk_host_test(test_ctap)
omk_host_test(test_store)

# Replay regression for the CTAPHID fuzz harness: the same inputs must produce
# byte-identical packet capture even when interleaved with other inputs in a
# different order.  This catches leaked channel/time/RNG state.
add_executable(test_fuzz_ctaphid_replay fuzz_ctaphid.c)
target_link_libraries(test_fuzz_ctaphid_replay PRIVATE omk_core)
target_compile_definitions(test_fuzz_ctaphid_replay PRIVATE
    OMK_FUZZ_CTAPHID_SELFTEST)
target_compile_options(test_fuzz_ctaphid_replay PRIVATE
    -std=c17 ${OMK_WARNINGS})
if(OMK_SANITIZE)
    target_compile_options(test_fuzz_ctaphid_replay PRIVATE ${OMK_SAN_FLAGS})
    target_link_options(test_fuzz_ctaphid_replay PRIVATE ${OMK_SAN_LINK_FLAGS})
endif()
add_test(NAME test_fuzz_ctaphid_replay COMMAND test_fuzz_ctaphid_replay)
set_tests_properties(test_fuzz_ctaphid_replay
    PROPERTIES ENVIRONMENT "${OMK_TEST_ENV}")

# Build-level regression for the configurable getInfo firmware version: check
# the alias expands to the configured value and that omk_ctap.c encodes that
# value for CBOR key 14, without redefining the macro.
if(OMK_SANITIZE)
    string(REPLACE ";" "|" OMK_SAN_FLAGS_ARG "${OMK_SAN_FLAGS}")
    string(REPLACE ";" "|" OMK_SAN_LINK_FLAGS_ARG "${OMK_SAN_LINK_FLAGS}")
    add_test(NAME host.ubsan_nonrecoverable
        COMMAND ${CMAKE_COMMAND}
            -DOMK_C_COMPILER=${CMAKE_C_COMPILER}
            -DOMK_SAN_FLAGS=${OMK_SAN_FLAGS_ARG}
            -DOMK_SAN_LINK_FLAGS=${OMK_SAN_LINK_FLAGS_ARG}
            -DOMK_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/ubsan-probe
            -P ${CMAKE_CURRENT_SOURCE_DIR}/check_ubsan_nonrecover.cmake)
endif()

add_test(NAME host.firmware_version_definition
    COMMAND ${CMAKE_COMMAND}
        -DOMK_C_COMPILER=${CMAKE_C_COMPILER}
        -DOMK_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/..
        -DOMK_EXPECTED_VERSION=${OMK_FIRMWARE_VERSION}
        -DOMK_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/firmware-version-probe
        -P ${CMAKE_CURRENT_SOURCE_DIR}/check_firmware_version.cmake)

# Practical instrumentation check: inspect the actual archive members instead
# of trusting that the compile options were applied.  The normal host core must
# stay free of libFuzzer coverage hooks.
function(omk_add_sancov_test test_name archive_target expectation work_name)
    if(NOT CMAKE_AR OR NOT CMAKE_NM)
        message(WARNING
            "CMAKE_AR/CMAKE_NM not available; skipping ${test_name}")
        return()
    endif()
    add_test(NAME ${test_name}
        COMMAND ${CMAKE_COMMAND}
            -DOMK_ARCHIVE=$<TARGET_FILE:${archive_target}>
            -DOMK_AR=${CMAKE_AR}
            -DOMK_NM=${CMAKE_NM}
            -DOMK_EXPECT=${expectation}
            -DOMK_EXPECTED_MEMBERS=${OMK_CORE_SOURCE_COUNT}
            -DOMK_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/${work_name}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/check_fuzz_sancov.cmake)
endfunction()

omk_add_sancov_test(host.core_without_fuzzer_hooks omk_core absent
    sancov-check-core)

if(OMK_FUZZ)
    include(CheckCSourceCompiles)
    unset(OMK_LIBFUZZER_AVAILABLE CACHE)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
    set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=fuzzer")
    check_c_source_compiles("
        int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
            (void)data;
            (void)size;
            return 0;
        }" OMK_LIBFUZZER_AVAILABLE)
    unset(CMAKE_REQUIRED_FLAGS)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)

    if(NOT OMK_LIBFUZZER_AVAILABLE)
        message(FATAL_ERROR
            "libFuzzer runtime not found for ${CMAKE_C_COMPILER}.\n"
            "Use a Clang that ships compiler-rt/libFuzzer:\n"
            "  Linux:  cmake --preset fuzz -DCMAKE_C_COMPILER=clang\n"
            "  macOS:  brew install llvm\n"
            "          rm -rf build/fuzz\n"
            "          cmake --preset fuzz "
            "-DCMAKE_C_COMPILER=\"$(brew --prefix llvm)/bin/clang\"")
    endif()

    # Instrumented copy of the *core*, not just the harness: fuzzer coverage
    # and ASan/UBSan are compiled in here, while --no-link keeps libFuzzer's
    # main() out of the library.  The normal omk_core above stays clean.
    add_library(omk_core_fuzz STATIC ${OMK_CORE_SOURCES})
    target_include_directories(omk_core_fuzz PUBLIC ../src)
    target_compile_definitions(omk_core_fuzz PRIVATE
        OMK_FIRMWARE_VERSION=${OMK_FIRMWARE_VERSION})
    target_compile_options(omk_core_fuzz PRIVATE
        -std=c17
        ${OMK_WARNINGS}
        -fsanitize=fuzzer-no-link,address,undefined
        -fno-sanitize-recover=all
        -fno-omit-frame-pointer)

    function(omk_fuzz_target target test_name source)
        add_executable(${target} ${source})
        target_link_libraries(${target} PRIVATE omk_core_fuzz)
        target_compile_options(${target} PRIVATE
            -std=c17
            ${OMK_WARNINGS}
            -fsanitize=fuzzer,address,undefined
            -fno-sanitize-recover=all
            -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fno-sanitize-recover=all)
        add_test(NAME ${test_name} COMMAND ${target} -runs=500 -seed=1)
        set_tests_properties(${test_name}
            PROPERTIES ENVIRONMENT "${OMK_TEST_ENV}")
    endfunction()

    # Parse/transport harnesses intentionally live in this build; they link the
    # instrumented core so `ctest --preset fuzz` covers real core code.
    omk_fuzz_target(omk_fuzz_cbor fuzz.cbor fuzz_cbor.c)
    omk_fuzz_target(omk_fuzz_ctaphid fuzz.ctaphid fuzz_ctaphid.c)

    # A short deterministic run makes `ctest --preset fuzz` meaningful even
    # when only the toolchain is being checked.
    add_executable(omk_fuzz_smoke fuzz_smoke.c)
    target_link_libraries(omk_fuzz_smoke PRIVATE omk_core_fuzz)
    target_compile_options(omk_fuzz_smoke PRIVATE
        -std=c17
        ${OMK_WARNINGS}
        -fsanitize=fuzzer,address,undefined
        -fno-sanitize-recover=all
        -fno-omit-frame-pointer)
    target_link_options(omk_fuzz_smoke PRIVATE
        -fsanitize=fuzzer,address,undefined
        -fno-sanitize-recover=all)
    add_test(NAME fuzz.smoke COMMAND omk_fuzz_smoke -runs=200 -seed=1)
    set_tests_properties(fuzz.smoke PROPERTIES ENVIRONMENT "${OMK_TEST_ENV}")

    omk_add_sancov_test(fuzz.core_has_sancov omk_core_fuzz present
        sancov-check-fuzz)
endif()

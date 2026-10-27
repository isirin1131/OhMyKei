# Host-side tests and fuzz targets.
#
# Everything under host/ must stay free of pico-sdk includes so it can run on
# the developer machine and in CI without an embedded toolchain.

set(OMK_WARNINGS -Wall -Wextra -Werror)
set(OMK_SAN_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)

add_executable(omk_host_build_smoke test_build_smoke.c)
target_compile_options(omk_host_build_smoke PRIVATE ${OMK_WARNINGS})

if(OMK_SANITIZE)
    target_compile_options(omk_host_build_smoke PRIVATE ${OMK_SAN_FLAGS})
    target_link_options(omk_host_build_smoke PRIVATE -fsanitize=address,undefined)
endif()

add_test(NAME host.build_smoke COMMAND omk_host_build_smoke)

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

    add_executable(omk_fuzz_smoke fuzz_smoke.c)
    target_compile_options(omk_fuzz_smoke PRIVATE
        ${OMK_WARNINGS}
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer)
    target_link_options(omk_fuzz_smoke PRIVATE
        -fsanitize=fuzzer,address,undefined)

    # A short deterministic run makes `ctest --preset fuzz` meaningful while
    # real parser harnesses are still being written.
    add_test(NAME fuzz.smoke COMMAND omk_fuzz_smoke -runs=200 -seed=1)
endif()

cmake_minimum_required(VERSION 3.25)

# ---------------------------------------------------------------------------
# Host build: pure C17, no pico-sdk. Used by unit tests and libFuzzer.
# ---------------------------------------------------------------------------
option(OMK_HOST_BUILD "Build host-side tests/fuzzers instead of firmware" OFF)
option(OMK_FUZZ "Build libFuzzer targets (host build only)" OFF)
option(OMK_SANITIZE "Enable ASan/UBSan for host builds" ON)

# Numeric firmware version reported by CTAP getInfo (CBOR key 14).  This is a
# build/configuration value, not a claim of FIDO certification or release
# conformance; release qualification is tracked separately.
set(OMK_FIRMWARE_VERSION "1" CACHE STRING
    "Numeric firmware version reported by CTAP getInfo")
if(NOT OMK_FIRMWARE_VERSION MATCHES "^(0|[1-9][0-9]*)$")
    message(FATAL_ERROR
        "OMK_FIRMWARE_VERSION must be a non-negative decimal integer "
        "without leading zeros (got '${OMK_FIRMWARE_VERSION}')")
endif()
if(OMK_FIRMWARE_VERSION GREATER 4294967295)
    message(FATAL_ERROR
        "OMK_FIRMWARE_VERSION must fit in a CTAP unsigned integer "
        "(got '${OMK_FIRMWARE_VERSION}')")
endif()

# Reproducible builds: strip the absolute checkout prefix from debug info and
# __FILE__ (and thus assertions) where the compiler supports it.  The flags are
# also used by the host build so test binaries reproduce across work trees.
function(omk_enable_reproducible_prefix_maps)
    include(CheckCCompilerFlag)
    check_c_compiler_flag(
        "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
        OMK_CC_HAS_FILE_PREFIX_MAP)
    check_c_compiler_flag(
        "-fdebug-prefix-map=${CMAKE_SOURCE_DIR}=."
        OMK_CC_HAS_DEBUG_PREFIX_MAP)
    check_c_compiler_flag(
        "-fmacro-prefix-map=${CMAKE_SOURCE_DIR}=."
        OMK_CC_HAS_MACRO_PREFIX_MAP)
    if(OMK_CC_HAS_FILE_PREFIX_MAP)
        add_compile_options(
            "$<$<COMPILE_LANGUAGE:C,CXX>:-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.>")
    elseif(OMK_CC_HAS_DEBUG_PREFIX_MAP)
        add_compile_options(
            "$<$<COMPILE_LANGUAGE:C,CXX>:-fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.>")
    endif()
    if(OMK_CC_HAS_MACRO_PREFIX_MAP)
        add_compile_options(
            "$<$<COMPILE_LANGUAGE:C,CXX>:-fmacro-prefix-map=${CMAKE_SOURCE_DIR}=.>")
    endif()
endfunction()

if(OMK_HOST_BUILD)
    project(ohmykei_host VERSION 0.1.0 LANGUAGES C)
    set(CMAKE_C_STANDARD 17)
    set(CMAKE_C_STANDARD_REQUIRED ON)
    set(CMAKE_C_EXTENSIONS OFF)
    enable_testing()
    add_subdirectory(host)
    return()
endif()

# ---------------------------------------------------------------------------
# Firmware build: pico-sdk, RP2350 (Cortex-M33), 2 MB flash.
# ---------------------------------------------------------------------------
# The RP2350-Zero-CM is the upstream Zero with 2 MB instead of 4 MB of flash;
# use the SDK board header as-is and override only the flash region below.
set(PICO_BOARD "waveshare_rp2350_zero" CACHE STRING "Pico SDK board")

include(cmake/pico_sdk.cmake)

project(ohmykei VERSION 0.1.0 LANGUAGES C CXX ASM)
pico_sdk_init()

# The vendored linker fragments (cmake/linker/*.incl) and the flash-region
# override are written against exactly this SDK release.  Do not float to a
# different 2.3.x/3.x: section names and stack-guard hooks may change.
if(NOT PICO_SDK_VERSION_STRING VERSION_EQUAL "2.3.1")
    message(FATAL_ERROR
        "OhMyKei pins pico-sdk exactly 2.3.1 because the linker fragments are "
        "vendored against it (found ${PICO_SDK_VERSION_STRING})")
endif()

omk_enable_reproducible_prefix_maps()

# The protocol core uses sizeable fixed buffers; the pico default is only
# 2 KiB.  Reserve 32 KiB for the main stack.  Enabling the SDK stack guard
# loads MSPLIM from __StackBottom, so the hardware faults on a stack overflow
# instead of silently walking into the heap/static data.
add_compile_definitions(PICO_STACK_SIZE=0x8000 PICO_USE_STACK_GUARDS=1)

if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR
        "The firmware requires arm-none-eabi-gcc (found ${CMAKE_C_COMPILER_ID})")
endif()

if(CMAKE_C_COMPILER_VERSION VERSION_LESS "13.2")
    message(FATAL_ERROR
        "arm-none-eabi-gcc >=13.2 required (found ${CMAKE_C_COMPILER_VERSION})")
elseif(CMAKE_C_COMPILER_VERSION VERSION_LESS "14.2")
    message(WARNING
        "Tested with arm-none-eabi-gcc 14.2+; "
        "${CMAKE_C_COMPILER_VERSION} is untested")
endif()

find_program(OMK_PICOTOOL picotool REQUIRED)
execute_process(
    COMMAND ${OMK_PICOTOOL} version
    OUTPUT_VARIABLE OMK_PICOTOOL_VERSION_OUTPUT
    ERROR_QUIET
    RESULT_VARIABLE OMK_PICOTOOL_VERSION_RESULT)
if(NOT OMK_PICOTOOL_VERSION_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to run '${OMK_PICOTOOL} version'")
endif()
string(REGEX MATCH "v([0-9]+\\.[0-9]+\\.[0-9]+)" _
    "${OMK_PICOTOOL_VERSION_OUTPUT}")
set(OMK_PICOTOOL_VERSION "${CMAKE_MATCH_1}")
if(NOT OMK_PICOTOOL_VERSION OR
   OMK_PICOTOOL_VERSION VERSION_LESS "2.3.1" OR
   OMK_PICOTOOL_VERSION VERSION_GREATER_EQUAL "3.0.0")
    message(FATAL_ERROR
        "picotool >=2.3.1 and <3.0.0 required (found "
        "'${OMK_PICOTOOL_VERSION_OUTPUT}')")
endif()

get_filename_component(OMK_TOOLCHAIN_BIN "${CMAKE_C_COMPILER}" DIRECTORY)
find_program(OMK_SIZE arm-none-eabi-size HINTS "${OMK_TOOLCHAIN_BIN}" REQUIRED)

include(cmake/core-sources.cmake)

add_library(omk_core STATIC ${OMK_CORE_SOURCES})
target_include_directories(omk_core PUBLIC src)
target_compile_options(omk_core PRIVATE -std=c17 -Wall -Wextra -Werror)
target_compile_definitions(omk_core PRIVATE
    OMK_FIRMWARE_VERSION=${OMK_FIRMWARE_VERSION})

set(OMK_FIRMWARE_SOURCES
    src/main.c
    src/platform/bootsel.c
    src/platform/platform.c
    src/platform/usb_descriptors.c
)

add_executable(ohmykei ${OMK_FIRMWARE_SOURCES})

# The CTAP core needs a larger stack than the 2 KiB pico default.  Put the
# stack in regular SRAM instead of the 4 KiB SCRATCH_Y region.
pico_add_linker_script_override_path(ohmykei ${CMAKE_CURRENT_SOURCE_DIR}/cmake/linker)

target_include_directories(ohmykei PRIVATE src src/platform)

# The only hardware difference from the upstream Zero: 2 MB instead of 4 MB.
# This generates a 2 MB pico_flash_region.ld for this target and adds the
# matching PICO_FLASH_SIZE_BYTES compile definition.
pico_override_flash_size(ohmykei 2097152)

# Compile-time consistency check between the core's fixed storage-region
# constants (src/omk_port.h), the 4 KiB sector size and the flash size handed
# to the linker.  This deliberately does not touch platform logic: a generated
# assertion-only TU is added to the firmware target.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/linker/region_check.c.in
    ${CMAKE_CURRENT_BINARY_DIR}/omk_region_check.c
    COPYONLY)
target_sources(ohmykei PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/omk_region_check.c)

# Strict flags apply only to project sources: pico-sdk sources are compiled
# into the same CMake target, so target-wide -Werror would make SDK upgrades
# fragile. The SDK keeps its GNU extensions; project code stays strict C17.
set(OMK_STRICT_SOURCES
    ${OMK_FIRMWARE_SOURCES}
    ${CMAKE_CURRENT_BINARY_DIR}/omk_region_check.c)
set_source_files_properties(
    ${OMK_STRICT_SOURCES}
    PROPERTIES COMPILE_OPTIONS "-std=c17;-Wall;-Wextra;-Werror")

target_link_libraries(ohmykei PRIVATE
    omk_core pico_stdlib pico_status_led hardware_flash pico_rand
    tinyusb_device tinyusb_board)

# Console: USB CDC only (the CM has no exposed UART pins).
pico_enable_stdio_usb(ohmykei 0)
pico_enable_stdio_uart(ohmykei 0)

# ohmykei.uf2/.bin/.hex/.dis/.map plus binary info.
pico_add_extra_outputs(ohmykei)

add_custom_target(flash
    COMMAND ${OMK_PICOTOOL} load -f -x $<TARGET_FILE:ohmykei>
    DEPENDS ohmykei
    USES_TERMINAL
    COMMENT "Flashing ohmykei with picotool"
)

add_custom_target(size
    COMMAND ${OMK_SIZE} -B $<TARGET_FILE:ohmykei>
    DEPENDS ohmykei
    USES_TERMINAL
    COMMENT "ohmykei firmware size"
)

# Committed check of the real ELF symbols, so a future edit cannot silently
# weaken the linker assertions into tautologies.
add_custom_target(layout-check
    COMMAND ${CMAKE_COMMAND}
        -DOMK_ELF=$<TARGET_FILE:ohmykei>
        -DOMK_NM=${CMAKE_NM}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/linker/check_layout.cmake
    DEPENDS ohmykei
    USES_TERMINAL
    COMMENT "Checking firmware flash/stack layout symbols"
)

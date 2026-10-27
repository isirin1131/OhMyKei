cmake_minimum_required(VERSION 3.25)

# ---------------------------------------------------------------------------
# Host build: pure C17, no pico-sdk. Used by unit tests and libFuzzer.
# ---------------------------------------------------------------------------
option(OMK_HOST_BUILD "Build host-side tests/fuzzers instead of firmware" OFF)
option(OMK_FUZZ "Build libFuzzer targets (host build only)" OFF)
option(OMK_SANITIZE "Enable ASan/UBSan for host builds" ON)

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

if(PICO_SDK_VERSION_STRING VERSION_LESS "2.3.1" OR
   PICO_SDK_VERSION_STRING VERSION_GREATER_EQUAL "3.0.0")
    message(FATAL_ERROR
        "OhMyKei requires pico-sdk >=2.3.1 and <3.0.0 "
        "(found ${PICO_SDK_VERSION_STRING})")
endif()

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

set(OMK_FIRMWARE_SOURCES
    src/main.c
    src/platform/bootsel.c
)

add_executable(ohmykei ${OMK_FIRMWARE_SOURCES})

target_include_directories(ohmykei PRIVATE src)

# The only hardware difference from the upstream Zero: 2 MB instead of 4 MB.
# This generates a 2 MB pico_flash_region.ld for this target and adds the
# matching PICO_FLASH_SIZE_BYTES compile definition.
pico_override_flash_size(ohmykei 2097152)

# Strict flags apply only to project sources: pico-sdk sources are compiled
# into the same CMake target, so target-wide -Werror would make SDK upgrades
# fragile. The SDK keeps its GNU extensions; project code stays strict C17.
set_source_files_properties(
    ${OMK_FIRMWARE_SOURCES}
    PROPERTIES COMPILE_OPTIONS "-std=c17;-Wall;-Wextra;-Werror")

target_link_libraries(ohmykei PRIVATE pico_stdlib pico_status_led)

# Console: USB CDC only (the CM has no exposed UART pins).
pico_enable_stdio_usb(ohmykei 1)
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

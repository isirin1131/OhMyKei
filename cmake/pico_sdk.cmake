# Locate the Raspberry Pi Pico SDK before project()/pico_sdk_init().
#
# Search order:
#   1. -DPICO_SDK_PATH=/path/to/pico-sdk
#   2. PICO_SDK_PATH in the environment
#   3. ~/.pico-sdk/sdk/2.3.1  (Raspberry Pi VS Code extension layout)
#   4. ~/pico-sdk
#
# There is deliberately no implicit network fetch: a missing SDK is a setup
# error, not a surprise clone of a multi-hundred-megabyte repository.

if(NOT PICO_SDK_PATH AND DEFINED ENV{PICO_SDK_PATH})
    set(PICO_SDK_PATH "$ENV{PICO_SDK_PATH}")
endif()

if(NOT PICO_SDK_PATH)
    foreach(candidate
            "$ENV{HOME}/.pico-sdk/sdk/2.3.1"
            "$ENV{HOME}/pico-sdk")
        if(EXISTS "${candidate}/pico_sdk_init.cmake")
            set(PICO_SDK_PATH "${candidate}")
            break()
        endif()
    endforeach()
endif()

if(NOT PICO_SDK_PATH OR NOT EXISTS "${PICO_SDK_PATH}/pico_sdk_init.cmake")
    message(FATAL_ERROR
        "pico-sdk 2.3.1 not found (PICO_SDK_PATH='${PICO_SDK_PATH}').\n"
        "Set -DPICO_SDK_PATH=/path/to/pico-sdk or export PICO_SDK_PATH.\n"
        "Install it with:\n"
        "  git clone --branch 2.3.1 --depth 1 --recurse-submodules \\\n"
        "    https://github.com/raspberrypi/pico-sdk.git ~/.pico-sdk/sdk/2.3.1")
endif()

message(STATUS "Using pico-sdk at ${PICO_SDK_PATH}")

# The official import script sets up the platform/toolchain and defines
# pico_sdk_init(). Keeping the SDK's own copy avoids a vendored fork.
include("${PICO_SDK_PATH}/external/pico_sdk_import.cmake")

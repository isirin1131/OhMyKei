# Inspect the actual firmware ELF and assert the stack/heap/flash layout.
#
# This complements the linker ASSERTs: a regression that accidentally makes an
# assertion tautological, or removes a symbol, still fails this committed check.
#
# Expected RP2350 layout:
#   RAM top                 0x20080000
#   main stack              32 KiB, bottom at RAM top - 0x8000
#   __StackLimit            == stack bottom (pico_malloc heap ceiling)
#   __HeapLimit             == stack bottom (core uses no heap)
#   __end__                 below the stack/heap ceiling
#   __flash_binary_end      <= XIP 0x10100000 (upper 1 MiB store start)

cmake_minimum_required(VERSION 3.25)

foreach(required IN ITEMS OMK_ELF OMK_NM)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "layout check: ${required} is not set")
    endif()
endforeach()
if(NOT EXISTS "${OMK_ELF}")
    message(FATAL_ERROR "layout check: '${OMK_ELF}' does not exist")
endif()
if(NOT EXISTS "${OMK_NM}")
    message(FATAL_ERROR "layout check: nm '${OMK_NM}' does not exist")
endif()

execute_process(
    COMMAND "${OMK_NM}" "${OMK_ELF}"
    RESULT_VARIABLE nm_rc
    OUTPUT_VARIABLE nm_out
    ERROR_VARIABLE nm_err)
if(NOT nm_rc EQUAL 0)
    message(FATAL_ERROR
        "layout check: '${OMK_NM}' failed (${nm_rc}): ${nm_err}")
endif()

set(symbols
    __StackTop
    __StackBottom
    __StackLimit
    __HeapLimit
    __end__
    __flash_binary_end)
foreach(symbol IN LISTS symbols)
    unset(${symbol})
endforeach()

string(REPLACE "\n" ";" nm_lines "${nm_out}")
foreach(line IN LISTS nm_lines)
    if(line MATCHES "^([0-9a-fA-F]+)[ \t]+[A-Za-z][ \t]+([A-Za-z_][A-Za-z0-9_]*)$")
        set(symbol "${CMAKE_MATCH_2}")
        if(symbol IN_LIST symbols)
            math(EXPR "${symbol}" "0x${CMAKE_MATCH_1}")
        endif()
    endif()
endforeach()

foreach(symbol IN LISTS symbols)
    if(NOT DEFINED ${symbol})
        message(FATAL_ERROR
            "layout check: firmware is missing linker symbol ${symbol}")
    endif()
endforeach()

math(EXPR stack_size "${__StackTop} - ${__StackBottom}")
math(EXPR store_start "0x10100000")

if(NOT stack_size EQUAL 32768)
    message(FATAL_ERROR
        "layout check: main stack is ${stack_size} bytes, expected 32768")
endif()
if(NOT "${__StackLimit}" EQUAL "${__StackBottom}")
    message(FATAL_ERROR
        "layout check: __StackLimit (${__StackLimit}) is not stack bottom "
        "(${__StackBottom})")
endif()
if(NOT "${__HeapLimit}" EQUAL "${__StackBottom}")
    message(FATAL_ERROR
        "layout check: __HeapLimit (${__HeapLimit}) is not stack bottom "
        "(${__StackBottom}); heap could grow into live stack")
endif()
if(NOT "${__end__}" LESS "${__HeapLimit}")
    message(FATAL_ERROR
        "layout check: static data end (${__end__}) does not leave room below "
        "the heap/stack ceiling (${__HeapLimit})")
endif()
if("${__flash_binary_end}" GREATER "${store_start}")
    message(FATAL_ERROR
        "layout check: firmware image ends at ${__flash_binary_end}, past the "
        "upper 1 MiB store at ${store_start}")
endif()

message(STATUS
    "layout check: stack ${__StackBottom}..${__StackTop} (32 KiB), "
    "StackLimit/HeapLimit=${__StackLimit}, end=${__end__}, "
    "flash_end=${__flash_binary_end} <= ${store_start}")

# Verify that every object in a core archive does (or does not) contain
# libFuzzer's SanitizerCoverage instrumentation.
#
# Invoked by host/CMakeLists.txt as a CTest so the check runs against the real
# archive produced by the current compiler, not against a comment.
#
# Required variables:
#   OMK_ARCHIVE          static archive to inspect
#   OMK_AR               archiver command
#   OMK_NM               symbol lister command
#   OMK_EXPECT           "present" or "absent"
#   OMK_WORK_DIR         scratch directory (must look like .../sancov-check-*)
# Optional:
#   OMK_EXPECTED_MEMBERS number of object members expected

cmake_minimum_required(VERSION 3.25)

foreach(required IN ITEMS OMK_ARCHIVE OMK_AR OMK_NM OMK_EXPECT OMK_WORK_DIR)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "sancov check: ${required} is not set")
    endif()
endforeach()

if(NOT OMK_EXPECT MATCHES "^(present|absent)$")
    message(FATAL_ERROR
        "sancov check: OMK_EXPECT must be present or absent, got '${OMK_EXPECT}'")
endif()

if(NOT EXISTS "${OMK_ARCHIVE}")
    message(FATAL_ERROR "sancov check: archive '${OMK_ARCHIVE}' does not exist")
endif()

# Never recursively delete an arbitrary caller-supplied path.
if(NOT OMK_WORK_DIR MATCHES "/sancov-check-[^/]+/?$")
    message(FATAL_ERROR
        "sancov check: refusing unsafe scratch directory '${OMK_WORK_DIR}'")
endif()

file(REMOVE_RECURSE "${OMK_WORK_DIR}")
file(MAKE_DIRECTORY "${OMK_WORK_DIR}")

execute_process(
    COMMAND "${OMK_AR}" t "${OMK_ARCHIVE}"
    RESULT_VARIABLE ar_list_rc
    OUTPUT_VARIABLE archive_members
    ERROR_VARIABLE ar_list_err)
if(NOT ar_list_rc EQUAL 0)
    message(FATAL_ERROR
        "sancov check: '${OMK_AR} t' failed (${ar_list_rc}): ${ar_list_err}")
endif()

string(REPLACE "\n" ";" member_list "${archive_members}")
list(FILTER member_list EXCLUDE REGEX "SYMDEF")
list(FILTER member_list EXCLUDE REGEX "^/")
list(FILTER member_list EXCLUDE REGEX "^$")
list(LENGTH member_list member_count)

if(DEFINED OMK_EXPECTED_MEMBERS AND NOT "${OMK_EXPECTED_MEMBERS}" STREQUAL "")
    if(NOT member_count EQUAL OMK_EXPECTED_MEMBERS)
        message(FATAL_ERROR
            "sancov check: archive has ${member_count} members, expected "
            "${OMK_EXPECTED_MEMBERS}: ${member_list}")
    endif()
endif()

execute_process(
    COMMAND "${OMK_AR}" x "${OMK_ARCHIVE}"
    WORKING_DIRECTORY "${OMK_WORK_DIR}"
    RESULT_VARIABLE ar_extract_rc
    OUTPUT_VARIABLE ar_extract_out
    ERROR_VARIABLE ar_extract_err)
if(NOT ar_extract_rc EQUAL 0)
    message(FATAL_ERROR
        "sancov check: '${OMK_AR} x' failed (${ar_extract_rc}): "
        "${ar_extract_err}${ar_extract_out}")
endif()

file(GLOB objects "${OMK_WORK_DIR}/*.o" "${OMK_WORK_DIR}/*.obj")
list(LENGTH objects object_count)
if(object_count EQUAL 0)
    message(FATAL_ERROR
        "sancov check: no object files extracted from '${OMK_ARCHIVE}'")
endif()
if(DEFINED OMK_EXPECTED_MEMBERS AND NOT "${OMK_EXPECTED_MEMBERS}" STREQUAL "")
    if(NOT object_count EQUAL OMK_EXPECTED_MEMBERS)
        message(FATAL_ERROR
            "sancov check: extracted ${object_count} objects, expected "
            "${OMK_EXPECTED_MEMBERS}: ${objects}")
    endif()
endif()

foreach(object IN LISTS objects)
    execute_process(
        COMMAND "${OMK_NM}" "${object}"
        RESULT_VARIABLE nm_rc
        OUTPUT_VARIABLE symbols
        ERROR_VARIABLE nm_err)
    if(NOT nm_rc EQUAL 0)
        message(FATAL_ERROR
            "sancov check: '${OMK_NM} ${object}' failed (${nm_rc}): ${nm_err}")
    endif()

    string(TOLOWER "${symbols}" symbols_lower)
    string(FIND "${symbols_lower}" "sancov" sancov_index)

    if(OMK_EXPECT STREQUAL "present")
        if(sancov_index EQUAL -1)
            message(FATAL_ERROR
                "sancov check: '${object}' has no SanitizerCoverage symbols; "
                "the fuzz core was not compiled with -fsanitize=fuzzer-no-link")
        endif()
    else()
        if(NOT sancov_index EQUAL -1)
            message(FATAL_ERROR
                "sancov check: '${object}' unexpectedly contains "
                "SanitizerCoverage symbols; the normal core leaked fuzz flags")
        endif()
    endif()
endforeach()

message(STATUS
    "sancov check: ${object_count} core objects: instrumentation ${OMK_EXPECT}")

# Helpers shared by TestListingGuard.cmake and CoverageLedger.cmake: the GoogleTest binary
# registry that tests/CMakeLists.txt writes, each binary's --gtest_list_tests, the ctest entry a
# case runs in, and a scan of the TEST bodies in the new test sources.
#
# Registry lines (<build>/tests/gtest-binaries.txt, one per gxbuild3_add_gtest binary):
#   name|prefix|path|bundles|per_row|skip_bundles      (lists comma-separated)

include_guard(GLOBAL)

# gxbuild3_gtest_encode(<out-list> <text>): one list element per line, with ; [ ] \ encoded as in
# LedgerCommon.cmake so that no line can split or merge list elements.
function(gxbuild3_gtest_encode out text)
    string(REPLACE "\r" "" text "${text}")
    string(REPLACE "\\" "@BS@" text "${text}")
    string(REPLACE ";" "@SC@" text "${text}")
    string(REPLACE "[" "@LB@" text "${text}")
    string(REPLACE "]" "@RB@" text "${text}")
    string(REPLACE "\n" ";" lines "${text}")
    set(${out} "${lines}" PARENT_SCOPE)
endfunction()

# gxbuild3_gtest_decode(<out> <text>): undo gxbuild3_gtest_encode on one line.
function(gxbuild3_gtest_decode out text)
    string(REPLACE "@SC@" ";" text "${text}")
    string(REPLACE "@LB@" "[" text "${text}")
    string(REPLACE "@RB@" "]" text "${text}")
    string(REPLACE "@BS@" "\\" text "${text}")
    set(${out} "${text}" PARENT_SCOPE)
endfunction()

# gxbuild3_gtest_key(<out> <text>): a variable-name-safe key for an arbitrary case or entry name.
function(gxbuild3_gtest_key out text)
    string(SHA1 key "${text}")
    set(${out} "${key}" PARENT_SCOPE)
endfunction()

# gxbuild3_gtest_load(<registry file>) sets, in the caller's scope:
#   GTEST_BINARIES                    binary target names, in registry order
#   GTEST_<name>_PREFIX/_PATH         the ctest prefix (without the '.') and the executable
#   GTEST_<name>_BUNDLES/_PER_ROW/_SKIP_BUNDLES   lists
#   GTEST_<name>_CASES                every listed case: Suite.Test or Inst/Suite.Test/Row
#   GTEST_<name>_RAW_PARAMS           listing lines whose parameter printed as raw bytes
# A binary that cannot be listed is a FATAL_ERROR.
macro(gxbuild3_gtest_load registry)
    if(NOT EXISTS "${registry}")
        message(FATAL_ERROR "GoogleTest registry ${registry} is missing; reconfigure the build")
    endif()
    file(STRINGS "${registry}" _gx_registry_lines)
    set(GTEST_BINARIES "")
    foreach(_gx_entry IN LISTS _gx_registry_lines)
        if(_gx_entry STREQUAL "")
            continue()
        endif()
        string(REPLACE "|" ";" _gx_fields "${_gx_entry}@END@")
        list(LENGTH _gx_fields _gx_count)
        if(NOT _gx_count EQUAL 6)
            message(FATAL_ERROR "malformed GoogleTest registry line: ${_gx_entry}")
        endif()
        list(GET _gx_fields 0 _gx_name)
        list(GET _gx_fields 1 GTEST_${_gx_name}_PREFIX)
        list(GET _gx_fields 2 GTEST_${_gx_name}_PATH)
        foreach(_gx_pair IN ITEMS "3;BUNDLES" "4;PER_ROW" "5;SKIP_BUNDLES")
            list(GET _gx_pair 0 _gx_index)
            list(GET _gx_pair 1 _gx_what)
            list(GET _gx_fields ${_gx_index} _gx_value)
            string(REPLACE "@END@" "" _gx_value "${_gx_value}")
            string(REPLACE "," ";" GTEST_${_gx_name}_${_gx_what} "${_gx_value}")
        endforeach()
        list(APPEND GTEST_BINARIES "${_gx_name}")

        execute_process(COMMAND "${GTEST_${_gx_name}_PATH}" --gtest_list_tests
            RESULT_VARIABLE _gx_result OUTPUT_VARIABLE _gx_out ERROR_VARIABLE _gx_err)
        if(NOT _gx_result EQUAL 0)
            message(FATAL_ERROR "${_gx_name} --gtest_list_tests failed (${_gx_result}): ${_gx_err}")
        endif()
        gxbuild3_gtest_encode(_gx_lines "${_gx_out}")
        set(GTEST_${_gx_name}_CASES "")
        set(GTEST_${_gx_name}_RAW_PARAMS "")
        set(_gx_suite "")
        foreach(_gx_line IN LISTS _gx_lines)
            if(_gx_line MATCHES "-byte object")
                list(APPEND GTEST_${_gx_name}_RAW_PARAMS "${_gx_line}")
            endif()
            if(_gx_line MATCHES "^([A-Za-z0-9_/]+)\\.( .*)?$")
                set(_gx_suite "${CMAKE_MATCH_1}")
            elseif(_gx_line MATCHES "^  ([A-Za-z0-9_/]+)( .*)?$" AND NOT _gx_suite STREQUAL "")
                list(APPEND GTEST_${_gx_name}_CASES "${_gx_suite}.${CMAKE_MATCH_1}")
            endif()
        endforeach()
    endforeach()
endmacro()

# gxbuild3_gtest_split(<case> <suite-var> <test-var>): Inst/Suite.Test/Row -> Inst/Suite, Test/Row.
function(gxbuild3_gtest_split case suite_var test_var)
    string(FIND "${case}" "." dot)
    string(SUBSTRING "${case}" 0 ${dot} suite)
    math(EXPR dot "${dot} + 1")
    string(SUBSTRING "${case}" ${dot} -1 test)
    set(${suite_var} "${suite}" PARENT_SCOPE)
    set(${test_var} "${test}" PARENT_SCOPE)
endfunction()

# gxbuild3_gtest_bundle_of(<out> <bundles> <case>): the BUNDLE entry whose filter selects the
# case (Suite -> Suite.* and */Suite.*, Inst/Suite -> Inst/Suite.*), or "" when it is discovered.
function(gxbuild3_gtest_bundle_of out bundles case)
    gxbuild3_gtest_split("${case}" suite test)
    set(found "")
    foreach(bundle IN LISTS bundles)
        if(suite STREQUAL bundle)
            set(found "${bundle}")
            break()
        endif()
        if(NOT bundle MATCHES "/" AND suite MATCHES "/${bundle}$")
            set(found "${bundle}")
            break()
        endif()
    endforeach()
    set(${out} "${found}" PARENT_SCOPE)
endfunction()

# gxbuild3_gtest_new_test(<out> <prefix> <bundles> <case>): the ledger's new_test spelling of a
# case: `<prefix>.<case>` when it is its own (discovered) ctest entry, otherwise
# `<prefix>.<bundle>#<label>` where label is the case minus its `<bundle>.` head (or the whole
# case when a Suite bundle selects an instantiation, Inst/Suite.Test/Row).
function(gxbuild3_gtest_new_test out prefix bundles case)
    gxbuild3_gtest_bundle_of(bundle "${bundles}" "${case}")
    if(bundle STREQUAL "")
        set(${out} "${prefix}.${case}" PARENT_SCOPE)
        return()
    endif()
    string(LENGTH "${bundle}." head)
    string(SUBSTRING "${case}" 0 ${head} start)
    if(start STREQUAL "${bundle}.")
        string(SUBSTRING "${case}" ${head} -1 label)
    else()
        set(label "${case}")
    endif()
    set(${out} "${prefix}.${bundle}#${label}" PARENT_SCOPE)
endfunction()

# gxbuild3_gtest_scan_sources(<tests dir>) reads every .cpp/.hpp under the area directories of
# tests/ (not golden/, gxBuild-support-files/, migration/ or scripts/) and sets:
#   GTEST_SRC_TESTS                  Suite.Test for every TEST/TEST_F/TEST_P body
#   GTEST_SRC_ASSERTS_<key>          EXPECT_*/ASSERT_*/matches_golden calls in that body
#                                    (key = gxbuild3_gtest_key of Suite.Test)
#   GTEST_SRC_SKIPPING_SUITES        suites with a GTEST_SKIP in one of their TEST bodies
#   GTEST_SRC_FORBIDDEN              "file:line: text" uses of CaptureStdout/CaptureStderr or
#                                    death tests
# A body ends at the first later non-blank line indented no deeper than its TEST line that is
# not a closing brace or a preprocessor line (sources are clang-formatted).
function(gxbuild3_gtest_scan_sources tests_dir)
    file(GLOB_RECURSE sources RELATIVE "${tests_dir}" "${tests_dir}/*/*.cpp" "${tests_dir}/*/*.hpp")
    list(FILTER sources EXCLUDE REGEX "^(golden|gxBuild-support-files|migration|scripts)/")
    list(SORT sources)
    set(tests "")
    set(skipping "")
    set(forbidden "")
    foreach(source IN LISTS sources)
        file(READ "${tests_dir}/${source}" text)
        gxbuild3_gtest_encode(lines "${text}")
        set(open "")
        set(open_indent 0)
        set(number 0)
        foreach(line IN LISTS lines)
            math(EXPR number "${number} + 1")
            if(line MATCHES "(CaptureStdout|CaptureStderr|(EXPECT|ASSERT)_(DEBUG_)?(DEATH|EXIT))")
                list(APPEND forbidden "${source}:${number}: ${CMAKE_MATCH_1}")
            endif()
            if(open AND line MATCHES "^([ ]*)([^ }#])")
                string(LENGTH "${CMAKE_MATCH_1}" indent)
                if(NOT indent GREATER open_indent)
                    set(GTEST_SRC_ASSERTS_${open_key} ${open_asserts} PARENT_SCOPE)
                    set(open "")
                endif()
            endif()
            if(line MATCHES "^([ ]*)TEST(_F|_P)?\\(([A-Za-z0-9_]+), ([A-Za-z0-9_]+)\\)")
                string(LENGTH "${CMAKE_MATCH_1}" open_indent)
                set(open_suite "${CMAKE_MATCH_3}")
                set(open "${CMAKE_MATCH_3}.${CMAKE_MATCH_4}")
                gxbuild3_gtest_key(open_key "${open}")
                set(open_asserts 0)
                list(APPEND tests "${open}")
                continue()
            endif()
            if(open)
                if(line MATCHES "(EXPECT|ASSERT)_|matches_golden")
                    string(REGEX MATCHALL "((EXPECT|ASSERT)_[A-Z0-9_]+\\(|matches_golden)" hits
                        "${line}")
                    list(LENGTH hits n)
                    math(EXPR open_asserts "${open_asserts} + ${n}")
                endif()
                if(line MATCHES "GTEST_SKIP")
                    list(APPEND skipping "${open_suite}")
                endif()
            endif()
        endforeach()
        if(open)
            set(GTEST_SRC_ASSERTS_${open_key} ${open_asserts} PARENT_SCOPE)
        endif()
    endforeach()
    list(REMOVE_DUPLICATES skipping)
    set(GTEST_SRC_TESTS "${tests}" PARENT_SCOPE)
    set(GTEST_SRC_SKIPPING_SUITES "${skipping}" PARENT_SCOPE)
    set(GTEST_SRC_FORBIDDEN "${forbidden}" PARENT_SCOPE)
endfunction()

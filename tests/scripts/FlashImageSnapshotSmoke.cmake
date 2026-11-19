cmake_minimum_required(VERSION 3.29)

# Smoke test of the byte oracle's snapshot tool (gxbuild3_flashimage_snapshot). The oracle
# (FlashImageTests.cmake) skips on a clean clone, so this keeps the tool exercised there:
#   1. --snapshot <tracked mydata/image.bin>: exit 0 and a non-empty stdout;
#   2. the same with --expect <that stdout>: exit 0 and the same stdout again;
#   3. --expect <that stdout with one value changed>: exit 1 and a "differs from" report;
#   4. no argument, an unknown argument, and --snapshot without its image: exit 2.
#
# Inputs (supplied with -D):
#   GXBUILD3_SNAPSHOT_TOOL  absolute path to the built gxbuild3_flashimage_snapshot
#   GXBUILD3_IMAGE          absolute path to tests/gxBuild-support-files/mydata/image.bin
#   GXBUILD3_SCRATCH_DIR    scratch directory of this test only; removed when it passes

foreach(required_var GXBUILD3_SNAPSHOT_TOOL GXBUILD3_IMAGE GXBUILD3_SCRATCH_DIR)
    if(NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
        message(FATAL_ERROR "${required_var} must be set")
    endif()
endforeach()
foreach(path "${GXBUILD3_SNAPSHOT_TOOL}" "${GXBUILD3_IMAGE}")
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "does not exist: ${path}")
    endif()
endforeach()

file(REMOVE_RECURSE "${GXBUILD3_SCRATCH_DIR}")
file(MAKE_DIRECTORY "${GXBUILD3_SCRATCH_DIR}")

set(problems "")

# expect_run(<name> <exit> <out_var> <err_var> <args>...): runs the tool, records a problem
# when it does not exit with <exit>, and returns its stdout and stderr.
function(expect_run name want out_var err_var)
    execute_process(
        COMMAND "${GXBUILD3_SNAPSHOT_TOOL}" ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE out
        ERROR_VARIABLE err)
    if(NOT result STREQUAL "${want}")
        set(problems ${problems} "${name}: exited ${result}, expected ${want}:\n${err}"
            PARENT_SCOPE)
    endif()
    set(${out_var} "${out}" PARENT_SCOPE)
    set(${err_var} "${err}" PARENT_SCOPE)
endfunction()

# 1. The snapshot of the tracked donor.
expect_run(snapshot 0 snapshot err --snapshot "${GXBUILD3_IMAGE}")
string(LENGTH "${snapshot}" snapshot_length)
if(snapshot_length EQUAL 0)
    list(APPEND problems "snapshot: the tool printed nothing")
elseif(NOT snapshot MATCHES "^input\\.size=0x[0-9A-F]+\n")
    list(APPEND problems "snapshot: stdout does not start with an input.size line")
endif()

# 2. --expect against its own output.
set(expected "${GXBUILD3_SCRATCH_DIR}/expected.txt")
file(WRITE "${expected}" "${snapshot}")
expect_run(expect_same 0 again err --snapshot "${GXBUILD3_IMAGE}" --expect "${expected}")
if(NOT again STREQUAL snapshot)
    list(APPEND problems "expect_same: the second snapshot differs from the first")
endif()

# 3. --expect against a perturbed copy.
string(REGEX REPLACE "^input\\.size=0x" "input.size=0y" perturbed "${snapshot}")
set(perturbed_file "${GXBUILD3_SCRATCH_DIR}/perturbed.txt")
file(WRITE "${perturbed_file}" "${perturbed}")
expect_run(expect_perturbed 1 out err --snapshot "${GXBUILD3_IMAGE}" --expect "${perturbed_file}")
if(NOT err MATCHES "differs from")
    list(APPEND problems "expect_perturbed: stderr does not report the difference:\n${err}")
endif()

# 4. Usage errors.
set(usage_cases no_argument unknown_argument snapshot_without_image)
set(no_argument_args "")
set(unknown_argument_args --snapshot "${GXBUILD3_IMAGE}" --bogus)
set(snapshot_without_image_args --snapshot)
foreach(case IN LISTS usage_cases)
    expect_run(${case} 2 out err ${${case}_args})
    if(NOT err MATCHES "usage: [^\n]* --snapshot <image> \\[--expect <file>\\]")
        list(APPEND problems "${case}: stderr has no usage line:\n${err}")
    endif()
endforeach()

if(problems)
    foreach(text IN LISTS problems)
        message("FAIL: ${text}")
    endforeach()
    message(FATAL_ERROR "flashimage snapshot smoke: failed (scratch kept in ${GXBUILD3_SCRATCH_DIR})")
endif()
file(REMOVE_RECURSE "${GXBUILD3_SCRATCH_DIR}")
message(STATUS "flashimage snapshot smoke: 6 runs ok, ${snapshot_length} bytes of snapshot")

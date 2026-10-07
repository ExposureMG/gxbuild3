cmake_minimum_required(VERSION 3.29)

# FlashImage byte oracle: run build_all.sh with the freshly built gxbuild in a scratch
# copy of the support directory and compare the SHA-256 of every image it writes with
# the tracked manifest tests/golden/build_all.sha256.
#
# The image names on build_all.sh's ./gxbuild lines (`-o <name>.bin`) are the manifest
# keys. Every build runs under SOURCE_DATE_EPOCH=1791105724 and TZ=UTC; build_all.sh
# itself is never edited. It starts with `rm -f *.log *.bin` and writes into its cwd, so
# it only ever runs in a scratch directory, never in the real support directory.
#
# Manifest format: one entry per line, `<sha256>  <image>` (sha256sum style), or
# `FAILED  <image>` for a build that currently writes no image although every input it
# names is present. `#` starts a comment line.
#
# Per entry:
#   - inputs present (the -b INI, the -i image, every -d directory, and for devgl the
#     signing key SB_priv.bin inside one of its -d roots): the outcome must equal the
#     manifest, otherwise the test fails and names the image.
#   - inputs absent: reported as "not compared" with the reason; never a failure.
#   - a build_all.sh image without a manifest entry fails (unpinned image).
#   - a manifest entry without a build_all.sh line is reported as "not compared".
# build_all.sh runs twice; every runnable image must be byte-identical across the two runs
# (`deterministic N/R`, R = entries with all inputs) and the first run must match the
# manifest. The run prints `compared N/M`. When no entry has its inputs (a clean clone,
# where the per-console fixture directories are absent) the test exits 77 so CTest
# reports a skip.
#
# Parse snapshots: the snapshot tool (gxbuild3_flashimage_golden_tests --snapshot <image>)
# prints the parse, decrypt and round-trip summary of one image. It runs over every image
# the first run wrote, and each output is compared with that image's `== <image>` section of
# the tracked tests/golden/build_all.parse.txt. A differing or missing section fails and
# names the image (with the first differing lines). The run prints `snapshots N/M`, M being
# the images the manifest expects plus any other golden section; an image whose inputs are
# absent is reported as "not snapshotted" with the reason.
#
# Capture mode (-DGXBUILD3_UPDATE_GOLDEN=1, never set by CTest; see the
# gxbuild3_flashimage_golden_update target): every input must be present, build_all.sh
# runs twice in two fresh scratch copies, the snapshot tool runs over both runs' images,
# and the manifest and the snapshot golden are written only when both runs produce
# identical outcomes and identical snapshots for every image.
#
# Inputs (supplied with -D):
#   GXBUILD3_EXE          absolute path to the built gxbuild executable
#   GXBUILD3_SUPPORT_DIR  absolute path to tests/gxBuild-support-files
#   GXBUILD3_BASH         absolute path to bash, or a *-NOTFOUND placeholder
#   GXBUILD3_GOLDEN       absolute path to tests/golden/build_all.sha256
#   GXBUILD3_SNAPSHOT_TOOL  absolute path to the built gxbuild3_flashimage_golden_tests
#   GXBUILD3_PARSE_GOLDEN   absolute path to tests/golden/build_all.parse.txt
#   GXBUILD3_SCRATCH_DIR  absolute scratch directory in the build tree
#   GXBUILD3_UPDATE_GOLDEN  optional; true selects capture mode

set(pinned_source_date_epoch 1791105724)

foreach(required_var GXBUILD3_EXE GXBUILD3_SUPPORT_DIR GXBUILD3_GOLDEN GXBUILD3_SCRATCH_DIR
        GXBUILD3_SNAPSHOT_TOOL GXBUILD3_PARSE_GOLDEN)
    if(NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
        message(FATAL_ERROR "${required_var} must be set")
    endif()
endforeach()
if(NOT EXISTS "${GXBUILD3_EXE}")
    message(FATAL_ERROR "gxbuild3 executable does not exist: ${GXBUILD3_EXE}")
endif()
if(NOT EXISTS "${GXBUILD3_SNAPSHOT_TOOL}")
    message(FATAL_ERROR "snapshot tool does not exist: ${GXBUILD3_SNAPSHOT_TOOL}")
endif()

get_filename_component(gxbuild_executable_name "${GXBUILD3_EXE}" NAME_WE)
if(NOT gxbuild_executable_name STREQUAL "gxbuild")
    message(FATAL_ERROR "the installed CLI artifact must be named gxbuild, got '${gxbuild_executable_name}'")
endif()

set(update_golden FALSE)
if(DEFINED GXBUILD3_UPDATE_GOLDEN AND GXBUILD3_UPDATE_GOLDEN)
    set(update_golden TRUE)
endif()

# cmake_language(EXIT) is how a `cmake -P` script hands CTest a skip status; it needs
# CMake >= 3.29, which is this project's floor.
function(skip_test reason)
    message(STATUS "SKIPPED: ${reason}")
    cmake_language(EXIT 77)
endfunction()

if(NOT DEFINED GXBUILD3_BASH OR GXBUILD3_BASH STREQUAL "" OR GXBUILD3_BASH MATCHES "-NOTFOUND$")
    skip_test("bash was not found, build_all.sh cannot run")
endif()
if(NOT IS_DIRECTORY "${GXBUILD3_SUPPORT_DIR}")
    skip_test("support-file fixtures are not present: ${GXBUILD3_SUPPORT_DIR}")
endif()
if(NOT EXISTS "${GXBUILD3_SUPPORT_DIR}/build_all.sh")
    skip_test("support-file fixtures are incomplete: ${GXBUILD3_SUPPORT_DIR}/build_all.sh is missing")
endif()

# --- build_all.sh entries ------------------------------------------------------------
# Each entry yields image, log and the list of inputs it needs. The log names are taken
# from the line because the script is uneven: the Zephyr retail log is
# '17559_retail_.log' with no console suffix.
file(STRINGS "${GXBUILD3_SUPPORT_DIR}/build_all.sh" build_script_lines REGEX "^\\./gxbuild ")
set(entries "")
foreach(line IN LISTS build_script_lines)
    if(NOT line MATCHES " -o ([^ ]+\\.bin)( |$)")
        message(FATAL_ERROR "build_all.sh: ./gxbuild line has no -o <image>.bin: ${line}")
    endif()
    set(image "${CMAKE_MATCH_1}")
    if(NOT line MATCHES "> *([^ ]+)[ ]*$")
        message(FATAL_ERROR "build_all.sh: ./gxbuild line has no '> <log>' redirect: ${line}")
    endif()
    set(log "${CMAKE_MATCH_1}")
    if(image IN_LIST entries)
        message(FATAL_ERROR "build_all.sh: image ${image} is written by more than one line")
    endif()
    list(APPEND entries "${image}")
    set(entry_log_${image} "${log}")

    set(missing "")
    set(data_dirs "")
    string(REGEX MATCHALL " -d [^ ]+" dir_flags "${line}")
    foreach(flag IN LISTS dir_flags)
        string(REGEX REPLACE "^ -d " "" data_dir "${flag}")
        list(APPEND data_dirs "${data_dir}")
        if(NOT IS_DIRECTORY "${GXBUILD3_SUPPORT_DIR}/${data_dir}")
            list(APPEND missing "${data_dir}/")
        endif()
    endforeach()
    foreach(file_flag b i)
        if(line MATCHES " -${file_flag} ([^ ]+)")
            if(NOT EXISTS "${GXBUILD3_SUPPORT_DIR}/${CMAKE_MATCH_1}")
                list(APPEND missing "${CMAKE_MATCH_1}")
            endif()
        endif()
    endforeach()
    # devgl images are signed with the private SB key, found through the -d roots.
    # It is only looked up in place; it is never copied, read or hashed here.
    if(line MATCHES " -t devgl:")
        set(have_sb_priv FALSE)
        foreach(data_dir IN LISTS data_dirs)
            if(EXISTS "${GXBUILD3_SUPPORT_DIR}/${data_dir}/SB_priv.bin")
                set(have_sb_priv TRUE)
            endif()
        endforeach()
        if(NOT have_sb_priv)
            list(APPEND missing "SB_priv.bin in a -d root")
        endif()
    endif()
    set(entry_missing_${image} "${missing}")
endforeach()
if(entries STREQUAL "")
    message(FATAL_ERROR "build_all.sh: found no ./gxbuild lines")
endif()

set(runnable_entries "")
foreach(image IN LISTS entries)
    if(entry_missing_${image} STREQUAL "")
        list(APPEND runnable_entries "${image}")
    endif()
endforeach()

# --- scratch copy and run ------------------------------------------------------------
# Copies every top-level entry of the support directory except the images and logs
# build_all.sh writes, the stale gxbuild binary and keys/. keys/ holds private key
# material and is linked, not copied, so it is only ever read in place.
function(stage_scratch scratch)
    file(REMOVE_RECURSE "${scratch}")
    file(MAKE_DIRECTORY "${scratch}")
    file(GLOB children LIST_DIRECTORIES true RELATIVE "${GXBUILD3_SUPPORT_DIR}"
        "${GXBUILD3_SUPPORT_DIR}/*")
    foreach(child IN LISTS children)
        if(child MATCHES "\\.(bin|log)$" OR child STREQUAL "gxbuild"
                OR child STREQUAL "gxbuild.exe")
            continue()
        endif()
        if(child STREQUAL "keys")
            file(CREATE_LINK "${GXBUILD3_SUPPORT_DIR}/keys" "${scratch}/keys"
                RESULT link_result SYMBOLIC)
            if(NOT link_result STREQUAL "0")
                message(FATAL_ERROR "linking keys/ into ${scratch}: ${link_result}")
            endif()
            continue()
        endif()
        file(COPY "${GXBUILD3_SUPPORT_DIR}/${child}" DESTINATION "${scratch}")
    endforeach()
    file(COPY_FILE "${GXBUILD3_EXE}" "${scratch}/gxbuild" RESULT copy_result)
    if(NOT copy_result STREQUAL "0")
        message(FATAL_ERROR "staging gxbuild into ${scratch}: ${copy_result}")
    endif()
endfunction()

# Runs build_all.sh in a fresh scratch copy and sets, in the caller's scope,
# <prefix>_<image> to the image's SHA-256 or FAILED for every runnable entry, and
# <prefix>_problems to the logs that recorded an error next to a written image.
function(run_build_all scratch prefix)
    stage_scratch("${scratch}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env
            "SOURCE_DATE_EPOCH=${pinned_source_date_epoch}" TZ=UTC LC_ALL=C
            "${GXBUILD3_BASH}" build_all.sh
        WORKING_DIRECTORY "${scratch}"
        RESULT_VARIABLE script_result
        OUTPUT_VARIABLE script_out
        ERROR_VARIABLE script_err)
    # build_all.sh has no `set -e`; its status only reflects the last line. The
    # per-image comparison below is the real check, so stderr is reported, not judged.
    message(STATUS "build_all.sh in ${scratch} exited ${script_result}")
    if(NOT script_err STREQUAL "")
        message(STATUS "build_all.sh stderr:\n${script_err}")
    endif()

    set(problems "")
    foreach(image IN LISTS runnable_entries)
        if(EXISTS "${scratch}/${image}")
            file(SHA256 "${scratch}/${image}" digest)
            set(${prefix}_${image} "${digest}" PARENT_SCOPE)
            set(log "${entry_log_${image}}")
            if(NOT EXISTS "${scratch}/${log}")
                list(APPEND problems "${image}: build_all.sh did not write the log ${log}")
            else()
                # spdlog renders levels as `[error]` / `[critical]` with the `[%l]`
                # pattern; the single-letter `%L` spellings are accepted too.
                file(STRINGS "${scratch}/${log}" log_lines REGEX "^\\[(error|critical|E|C)\\]")
                foreach(log_line IN LISTS log_lines)
                    list(APPEND problems "${image}: ${log} recorded a failure: ${log_line}")
                endforeach()
            endif()
        else()
            set(${prefix}_${image} "FAILED" PARENT_SCOPE)
        endif()
    endforeach()
    set(${prefix}_problems "${problems}" PARENT_SCOPE)
endfunction()

# Runs the snapshot tool over every image of runnable_entries that `scratch` holds and sets,
# in the caller's scope, <prefix>_snap_<image> to its output and <prefix>_snap_problems to
# the images it could not snapshot. Without `expect_dir` the outputs are only collected.
# With it, an image whose section file <expect_dir>/<image>.txt exists is compared with it
# by the tool itself (the first differing lines land in the problem), <prefix>_snap_matched
# lists the images that matched and an image with no section file is a problem.
function(snapshot_images scratch prefix expect_dir)
    set(problems "")
    set(matched "")
    foreach(image IN LISTS runnable_entries)
        if(NOT EXISTS "${scratch}/${image}")
            continue()
        endif()
        set(expect_args "")
        if(NOT expect_dir STREQUAL "")
            if(NOT EXISTS "${expect_dir}/${image}.txt")
                list(APPEND problems "${image}: no section in ${GXBUILD3_PARSE_GOLDEN}; recapture the golden")
                continue()
            endif()
            set(expect_args --expect "${expect_dir}/${image}.txt")
        endif()
        execute_process(
            COMMAND "${GXBUILD3_SNAPSHOT_TOOL}" --snapshot "${scratch}/${image}" ${expect_args}
            RESULT_VARIABLE snap_result
            OUTPUT_VARIABLE snap_out
            ERROR_VARIABLE snap_err)
        set(${prefix}_snap_${image} "${snap_out}" PARENT_SCOPE)
        if(snap_result STREQUAL "0")
            list(APPEND matched "${image}")
        elseif(expect_args STREQUAL "")
            list(APPEND problems "${image}: snapshot tool exited ${snap_result}:\n${snap_err}")
        else()
            list(APPEND problems "${image}: parse snapshot mismatch (exit ${snap_result}):\n${snap_err}")
        endif()
    endforeach()
    set(${prefix}_snap_problems "${problems}" PARENT_SCOPE)
    set(${prefix}_snap_matched "${matched}" PARENT_SCOPE)
endfunction()

function(report_not_runnable)
    foreach(image IN LISTS entries)
        if(NOT image IN_LIST runnable_entries)
            list(JOIN entry_missing_${image} ", " missing_list)
            message(STATUS "not compared: ${image}: missing input(s): ${missing_list}")
        endif()
    endforeach()
endfunction()

list(LENGTH entries entry_count)
list(LENGTH runnable_entries runnable_count)

# --- capture mode --------------------------------------------------------------------
if(update_golden)
    if(NOT runnable_count EQUAL entry_count)
        report_not_runnable()
        message(FATAL_ERROR
            "refusing to capture: ${runnable_count}/${entry_count} build_all.sh entries have "
            "all their inputs; a capture must cover every entry")
    endif()

    run_build_all("${GXBUILD3_SCRATCH_DIR}/capture-run1" first)
    run_build_all("${GXBUILD3_SCRATCH_DIR}/capture-run2" second)
    snapshot_images("${GXBUILD3_SCRATCH_DIR}/capture-run1" first "")
    snapshot_images("${GXBUILD3_SCRATCH_DIR}/capture-run2" second "")

    set(problems ${first_problems} ${second_problems} ${first_snap_problems}
        ${second_snap_problems})
    set(failed_builds "")
    foreach(image IN LISTS entries)
        if(NOT first_${image} STREQUAL second_${image})
            list(APPEND problems
                "${image}: nondeterministic: run 1 ${first_${image}}, run 2 ${second_${image}}")
        elseif(first_${image} STREQUAL "FAILED")
            list(APPEND failed_builds "${image}")
        elseif(NOT "${first_snap_${image}}" STREQUAL "${second_snap_${image}}")
            list(APPEND problems "${image}: parse snapshot differs between the two runs")
        elseif("${first_snap_${image}}" STREQUAL "")
            list(APPEND problems "${image}: the snapshot tool printed nothing")
        endif()
    endforeach()
    if(problems)
        list(JOIN problems "\n  " problem_text)
        message(FATAL_ERROR
            "refusing to write ${GXBUILD3_GOLDEN} and ${GXBUILD3_PARSE_GOLDEN}:\n  ${problem_text}")
    endif()

    set(manifest
        "# SHA-256 of every image tests/gxBuild-support-files/build_all.sh writes, keyed by the\n"
        "# image name on its ./gxbuild lines. Built with SOURCE_DATE_EPOCH=${pinned_source_date_epoch} TZ=UTC.\n"
        "# FAILED marks a build that writes no image although all of its inputs are present.\n"
        "# Checked by gxbuild3_flashimage_tests (tests/FlashImageTests.cmake). Regenerate with\n"
        "#   cmake --build build --target gxbuild3_flashimage_golden_update\n"
        "# which runs build_all.sh twice and writes only when both runs agree.\n")
    foreach(image IN LISTS entries)
        string(APPEND manifest "${first_${image}}  ${image}\n")
    endforeach()
    get_filename_component(golden_dir "${GXBUILD3_GOLDEN}" DIRECTORY)
    file(MAKE_DIRECTORY "${golden_dir}")
    file(WRITE "${GXBUILD3_GOLDEN}" ${manifest})

    string(CONCAT parse_golden
        "# Parse, decrypt and round-trip snapshot of every image build_all.sh writes, one\n"
        "# `== <image>` section each, printed by gxbuild3_flashimage_golden_tests --snapshot\n"
        "# under the CPU key public in build_all.sh. Console identities appear only as SHA-1.\n"
        "# Checked by gxbuild3_flashimage_tests (tests/FlashImageTests.cmake). Regenerate with\n"
        "#   cmake --build build --target gxbuild3_flashimage_golden_update\n"
        "# which snapshots both build_all.sh runs and writes only when they agree.\n")
    set(snapshot_count 0)
    foreach(image IN LISTS entries)
        if(first_${image} STREQUAL "FAILED")
            continue()
        endif()
        string(APPEND parse_golden "== ${image}\n${first_snap_${image}}")
        math(EXPR snapshot_count "${snapshot_count} + 1")
    endforeach()
    file(WRITE "${GXBUILD3_PARSE_GOLDEN}" "${parse_golden}")
    foreach(image IN LISTS failed_builds)
        message(WARNING "${image}: build_all.sh wrote no image with all inputs present; "
            "recorded as FAILED")
    endforeach()
    file(REMOVE_RECURSE "${GXBUILD3_SCRATCH_DIR}/capture-run1" "${GXBUILD3_SCRATCH_DIR}/capture-run2")
    message(STATUS "captured ${entry_count} entries into ${GXBUILD3_GOLDEN}; both runs identical")
    message(STATUS "captured ${snapshot_count} snapshots into ${GXBUILD3_PARSE_GOLDEN}; "
        "both runs identical")
    return()
endif()

# --- compare mode --------------------------------------------------------------------
if(NOT EXISTS "${GXBUILD3_GOLDEN}")
    message(FATAL_ERROR "golden manifest is missing: ${GXBUILD3_GOLDEN}")
endif()
file(STRINGS "${GXBUILD3_GOLDEN}" golden_lines)
set(golden_entries "")
foreach(golden_line IN LISTS golden_lines)
    if(golden_line STREQUAL "" OR golden_line MATCHES "^#")
        continue()
    endif()
    if(NOT golden_line MATCHES "^([0-9a-f]+|FAILED)  ([^ ]+)$")
        message(FATAL_ERROR "${GXBUILD3_GOLDEN}: malformed line: ${golden_line}")
    endif()
    set(expected "${CMAKE_MATCH_1}")
    set(image "${CMAKE_MATCH_2}")
    string(LENGTH "${expected}" expected_length)
    if(NOT expected STREQUAL "FAILED" AND NOT expected_length EQUAL 64)
        message(FATAL_ERROR "${GXBUILD3_GOLDEN}: malformed SHA-256 for ${image}: ${expected}")
    endif()
    if(image IN_LIST golden_entries)
        message(FATAL_ERROR "${GXBUILD3_GOLDEN}: duplicate entry ${image}")
    endif()
    list(APPEND golden_entries "${image}")
    set(golden_${image} "${expected}")
endforeach()

set(all_images ${golden_entries} ${entries})
list(REMOVE_DUPLICATES all_images)
list(LENGTH all_images total_count)

# The snapshot golden: `#` comment lines, then one `== <image>` section per image. Each
# section is written to <scratch>/expected/<image>.txt for the snapshot tool to compare.
# The text is only ever handled as a quoted string, never as a CMake list, so a `;` in a
# snapshot line is safe.
if(NOT EXISTS "${GXBUILD3_PARSE_GOLDEN}")
    message(FATAL_ERROR "golden parse snapshot is missing: ${GXBUILD3_PARSE_GOLDEN}")
endif()
set(expected_dir "${GXBUILD3_SCRATCH_DIR}/expected")
file(REMOVE_RECURSE "${expected_dir}")
file(MAKE_DIRECTORY "${expected_dir}")
file(READ "${GXBUILD3_PARSE_GOLDEN}" parse_text)
string(REPLACE "\r\n" "\n" parse_text "${parse_text}")
set(parse_text "\n${parse_text}")
set(snapshot_sections "")
string(FIND "${parse_text}" "\n== " marker)
if(marker GREATER 0)
    string(SUBSTRING "${parse_text}" 0 ${marker} parse_preamble)
    string(REGEX MATCH "\n[^#\n][^\n]*" stray_line "${parse_preamble}")
    if(NOT stray_line STREQUAL "")
        message(FATAL_ERROR "${GXBUILD3_PARSE_GOLDEN}: line before the first section: ${stray_line}")
    endif()
endif()
while(marker GREATER -1)
    math(EXPR header_start "${marker} + 4")
    string(SUBSTRING "${parse_text}" ${header_start} -1 parse_text)
    string(FIND "${parse_text}" "\n" header_end)
    if(header_end EQUAL -1)
        message(FATAL_ERROR "${GXBUILD3_PARSE_GOLDEN}: section header without a body")
    endif()
    string(SUBSTRING "${parse_text}" 0 ${header_end} section_image)
    if(NOT section_image MATCHES "^[A-Za-z0-9_.-]+\\.bin$")
        message(FATAL_ERROR "${GXBUILD3_PARSE_GOLDEN}: malformed section header: == ${section_image}")
    endif()
    if(section_image IN_LIST snapshot_sections)
        message(FATAL_ERROR "${GXBUILD3_PARSE_GOLDEN}: duplicate section ${section_image}")
    endif()
    list(APPEND snapshot_sections "${section_image}")
    math(EXPR body_start "${header_end} + 1")
    string(SUBSTRING "${parse_text}" ${body_start} -1 parse_text)
    string(FIND "${parse_text}" "\n== " marker)
    if(marker EQUAL -1)
        set(section_body "${parse_text}")
    else()
        math(EXPR body_length "${marker} + 1")
        string(SUBSTRING "${parse_text}" 0 ${body_length} section_body)
    endif()
    file(WRITE "${expected_dir}/${section_image}.txt" "${section_body}")
endwhile()

# Images with a snapshot: every golden section plus every image the manifest expects.
set(snapshot_images ${snapshot_sections})
foreach(image IN LISTS golden_entries)
    if(NOT golden_${image} STREQUAL "FAILED")
        list(APPEND snapshot_images "${image}")
    endif()
endforeach()
list(REMOVE_DUPLICATES snapshot_images)
list(LENGTH snapshot_images snapshot_total)

report_not_runnable()
foreach(image IN LISTS golden_entries)
    if(NOT image IN_LIST entries)
        message(STATUS "not compared: ${image}: build_all.sh has no line for it")
    endif()
endforeach()

if(runnable_count EQUAL 0)
    skip_test("compared 0/${total_count}, snapshots 0/${snapshot_total}: no build_all.sh "
        "entry has its inputs; the per-console fixture directories are absent")
endif()

# Determinism: build_all.sh runs twice, in two fresh scratch copies at different paths
# and times. An image whose two runs differ fails as nondeterministic rather than as a
# plain manifest mismatch, so a new source of randomness or wall-clock time is named as
# such. The first run is the one compared with the manifest.
run_build_all("${GXBUILD3_SCRATCH_DIR}/compare" actual)
run_build_all("${GXBUILD3_SCRATCH_DIR}/compare-rerun" rerun)

set(problems ${actual_problems} ${rerun_problems})
set(deterministic 0)
foreach(image IN LISTS runnable_entries)
    if(actual_${image} STREQUAL rerun_${image})
        math(EXPR deterministic "${deterministic} + 1")
    else()
        list(APPEND problems
            "${image}: nondeterministic: run 1 ${actual_${image}}, run 2 ${rerun_${image}}")
    endif()
endforeach()
message(STATUS "deterministic ${deterministic}/${runnable_count}")

set(compared 0)
foreach(image IN LISTS runnable_entries)
    set(got "${actual_${image}}")
    if(NOT DEFINED golden_${image})
        list(APPEND problems "${image}: no manifest entry (got ${got}); recapture the golden")
        continue()
    endif()
    set(expected "${golden_${image}}")
    if(got STREQUAL expected)
        math(EXPR compared "${compared} + 1")
        if(got STREQUAL "FAILED")
            message(STATUS "ok: ${image} (expected build failure)")
        else()
            message(STATUS "ok: ${image}")
        endif()
    elseif(got STREQUAL "FAILED")
        list(APPEND problems
            "${image}: build_all.sh wrote no image (expected ${expected}); see ${entry_log_${image}}")
    elseif(expected STREQUAL "FAILED")
        list(APPEND problems "${image}: now builds (${got}) but the manifest expects FAILED")
    else()
        list(APPEND problems "${image}: SHA-256 mismatch: expected ${expected}, got ${got}")
    endif()
endforeach()

message(STATUS "compared ${compared}/${total_count}")

# Parse snapshots of the first run's images against build_all.parse.txt.
snapshot_images("${GXBUILD3_SCRATCH_DIR}/compare" actual "${expected_dir}")
list(APPEND problems ${actual_snap_problems})
foreach(image IN LISTS actual_snap_matched)
    message(STATUS "snapshot ok: ${image}")
endforeach()
foreach(image IN LISTS snapshot_images)
    if(image IN_LIST actual_snap_matched)
        continue()
    elseif(NOT image IN_LIST entries)
        message(STATUS "not snapshotted: ${image}: build_all.sh has no line for it")
    elseif(NOT image IN_LIST runnable_entries)
        list(JOIN entry_missing_${image} ", " missing_list)
        message(STATUS "not snapshotted: ${image}: missing input(s): ${missing_list}")
    elseif(actual_${image} STREQUAL "FAILED")
        message(STATUS "not snapshotted: ${image}: build_all.sh wrote no image")
    elseif(NOT image IN_LIST snapshot_sections)
        message(STATUS "not snapshotted: ${image}: no section in the snapshot golden")
    else()
        message(STATUS "not snapshotted: ${image}: snapshot differs (see below)")
    endif()
endforeach()
foreach(image IN LISTS entries)
    if(NOT image IN_LIST snapshot_images AND image IN_LIST runnable_entries
            AND actual_${image} STREQUAL "FAILED")
        message(STATUS "no snapshot: ${image}: the manifest expects no image")
    endif()
endforeach()
list(LENGTH actual_snap_matched snapshot_matched_count)
message(STATUS "snapshots ${snapshot_matched_count}/${snapshot_total}")

if(problems)
    list(JOIN problems "\n  " problem_text)
    message(FATAL_ERROR "FlashImage byte oracle failed; scratch kept in "
        "${GXBUILD3_SCRATCH_DIR}/compare and ${GXBUILD3_SCRATCH_DIR}/compare-rerun:\n"
        "  ${problem_text}")
endif()
file(REMOVE_RECURSE "${GXBUILD3_SCRATCH_DIR}/compare" "${GXBUILD3_SCRATCH_DIR}/compare-rerun")

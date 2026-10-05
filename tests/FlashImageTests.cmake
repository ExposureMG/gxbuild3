cmake_minimum_required(VERSION 3.29)

# FlashImage build gate: run build_all.sh with the freshly built gxbuild and verify
# that every one of its 22 builds succeeded. Stage 1 checks the build gate only;
# FlashImage content verification is a later stage.
#
# Inputs (all supplied with -D by the registering add_test()):
#   GXBUILD3_EXE          absolute path to the built gxbuild executable
#   GXBUILD3_SUPPORT_DIR  absolute path to tests/gxBuild-support-files
#   GXBUILD3_BASH         absolute path to bash, or a *-NOTFOUND placeholder

if(NOT DEFINED GXBUILD3_EXE OR GXBUILD3_EXE STREQUAL "")
    message(FATAL_ERROR "GXBUILD3_EXE must name the gxbuild3 executable")
endif()
if(NOT EXISTS "${GXBUILD3_EXE}")
    message(FATAL_ERROR "gxbuild3 executable does not exist: ${GXBUILD3_EXE}")
endif()
if(NOT DEFINED GXBUILD3_SUPPORT_DIR OR GXBUILD3_SUPPORT_DIR STREQUAL "")
    message(FATAL_ERROR "GXBUILD3_SUPPORT_DIR must name the gxBuild-support-files directory")
endif()

get_filename_component(gxbuild_executable_name "${GXBUILD3_EXE}" NAME_WE)
if(NOT gxbuild_executable_name STREQUAL "gxbuild")
    message(FATAL_ERROR "the installed CLI artifact must be named gxbuild, got '${gxbuild_executable_name}'")
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

# The per-console directories build_all.sh passes with -d (zephyr/, jasper/, corona/)
# hold console-derived SMC and CB images, so they stay local and are not committed.
# Collect every -d directory from the active ./gxbuild lines and skip, rather than
# fail, when any of them is absent, as it is on a fresh clone.
file(STRINGS "${GXBUILD3_SUPPORT_DIR}/build_all.sh" build_script_lines REGEX "^\\./gxbuild ")
set(required_data_dirs "")
foreach(line IN LISTS build_script_lines)
    string(REGEX MATCHALL " -d [^ ]+" dir_flags "${line}")
    foreach(flag IN LISTS dir_flags)
        string(REGEX REPLACE "^ -d " "" data_dir "${flag}")
        list(APPEND required_data_dirs "${data_dir}")
    endforeach()
endforeach()
list(REMOVE_DUPLICATES required_data_dirs)
if(required_data_dirs STREQUAL "")
    message(FATAL_ERROR "build_all.sh: found no -d data directories on its ./gxbuild lines")
endif()
set(missing_data_dirs "")
foreach(data_dir IN LISTS required_data_dirs)
    if(NOT IS_DIRECTORY "${GXBUILD3_SUPPORT_DIR}/${data_dir}")
        list(APPEND missing_data_dirs "${data_dir}")
    endif()
endforeach()
if(missing_data_dirs)
    list(JOIN missing_data_dirs ", " missing_list)
    skip_test("local per-console fixtures are not present in ${GXBUILD3_SUPPORT_DIR}: ${missing_list}")
endif()

function(require_result name actual expected)
    if(NOT "${actual}" STREQUAL "${expected}")
        message(FATAL_ERROR "${name}: expected ${expected}, got ${actual}")
    endif()
endfunction()

# The image/log pairs below mirror the 22 invocations in build_all.sh. The log names
# are deliberately uneven because the script itself is: the Zephyr retail log is
# '17559_retail_.log' with no console suffix.
set(flashimage_builds
    # Small block XSB, Zephyr
    "17559_retail_zephyr.bin|17559_retail_.log"
    "17559_jtag_zephyr.bin|17559_jtag_zephyr.log"
    "17559_gg_zephyr.bin|17559_gg_zephyr.log"
    "17559_g2_zephyr.bin|17559_g2_zephyr.log"
    "17559_g2m_zephyr.bin|17559_g2m_zephyr.log"
    "17559_g3_zephyr.bin|17559_g3_zephyr.log"
    # New small block PSB, Jasper
    "17559_retail_jasper.bin|17559_retail_jasper.log"
    "17559_jtag_jasper.bin|17559_jtag_jasper.log"
    "17559_gg_jasper.bin|17559_gg_jasper.log"
    "17559_g2_jasper.bin|17559_g2_jasper.log"
    "17559_g2m_jasper.bin|17559_g2m_jasper.log"
    "17559_g3_jasper.bin|17559_g3_jasper.log"
    # Big block PSB, Jasper
    "17559_retail_jasperbb.bin|17559_retail_jasperbb.log"
    "17559_jtag_jasperbb.bin|17559_jtag_jasperbb.log"
    "17559_gg_jasperbb.bin|17559_gg_jasperbb.log"
    "17559_g2_jasperbb.bin|17559_g2_jasperbb.log"
    "17559_g2m_jasperbb.bin|17559_g2m_jasperbb.log"
    "17559_g3_jasperbb.bin|17559_g3_jasperbb.log"
    # eMMC, Corona 4G
    "17559_retail_corona4g.bin|17559_retail_corona4g.log"
    "17559_g2_corona4g.bin|17559_g2_corona4g.log"
    "17559_g2m_corona4g.bin|17559_g2m_corona4g.log"
    "17559_g3_corona4g.bin|17559_g3_corona4g.log")

# build_all.sh invokes ./gxbuild relative to its own directory, so stage the freshly
# built binary over whatever stale copy the fixtures ship with. RESULT is 0 on success
# or an error message otherwise, which keeps an unwritable support directory readable.
file(COPY_FILE "${GXBUILD3_EXE}" "${GXBUILD3_SUPPORT_DIR}/gxbuild" RESULT stage_result)
require_result("staging gxbuild into the support directory" "${stage_result}" "0")

execute_process(
    COMMAND "${GXBUILD3_BASH}" build_all.sh
    WORKING_DIRECTORY "${GXBUILD3_SUPPORT_DIR}"
    RESULT_VARIABLE script_result
    OUTPUT_VARIABLE script_out
    ERROR_VARIABLE script_err)

# build_all.sh has no `set -e`, so a non-zero status only proves the last invocation
# failed; the per-build checks below cover the earlier ones.
if(NOT script_result EQUAL 0)
    message(FATAL_ERROR
        "build_all.sh: expected exit 0, got ${script_result}\n"
        "stderr:\n${script_err}\n"
        "stdout:\n${script_out}")
endif()

# gxbuild reports command-line and input-resolution failures as `gxbuild: <message>`
# on stderr and exits non-zero. Only stdout is redirected into the per-build logs, so
# stderr is the only place those failures are visible.
string(REPLACE "\r\n" "\n" script_err "${script_err}")
string(REPLACE "\n" ";" stderr_lines "${script_err}")
foreach(line IN LISTS stderr_lines)
    if(line MATCHES "^gxbuild: ")
        message(FATAL_ERROR
            "build_all.sh: gxbuild reported a fatal command-line error on stderr: ${line}\n"
            "stdout:\n${script_out}")
    endif()
endforeach()

set(verified_builds 0)
foreach(entry IN LISTS flashimage_builds)
    string(REGEX MATCH "^([^|]+)\\|([^|]+)$" build_pair "${entry}")
    if(NOT build_pair)
        message(FATAL_ERROR "malformed image|log entry in the FlashImage build table: ${entry}")
    endif()
    set(image "${CMAKE_MATCH_1}")
    set(log "${CMAKE_MATCH_2}")

    if(NOT EXISTS "${GXBUILD3_SUPPORT_DIR}/${image}")
        message(FATAL_ERROR "${image}: build_all.sh did not write this image\nstdout:\n${script_out}")
    endif()
    if(NOT EXISTS "${GXBUILD3_SUPPORT_DIR}/${log}")
        message(FATAL_ERROR "${image}: build_all.sh did not write the log ${log}\nstdout:\n${script_out}")
    endif()

    # spdlog renders levels as short lowercase names with the `[%l] [%s] %v` pattern,
    # so an error or critical record starts a line with `[error]` or `[critical]`.
    # Redirected output carries no ANSI colour escapes. The single-letter spellings are
    # accepted too in case the pattern ever switches to `%L`.
    file(STRINGS "${GXBUILD3_SUPPORT_DIR}/${log}" log_lines)
    foreach(line IN LISTS log_lines)
        if(line MATCHES "^\\[(error|critical|E|C)\\]")
            message(FATAL_ERROR "${image}: ${log} recorded a failure: ${line}")
        endif()
    endforeach()

    math(EXPR verified_builds "${verified_builds} + 1")
endforeach()

message(STATUS "verified ${verified_builds} FlashImage builds from build_all.sh")

cmake_minimum_required(VERSION 3.25)

if(NOT DEFINED GXBUILD3_EXE OR GXBUILD3_EXE STREQUAL "")
    message(FATAL_ERROR "GXBUILD3_EXE must name the gxbuild3 executable")
endif()
if(NOT EXISTS "${GXBUILD3_EXE}")
    message(FATAL_ERROR "gxbuild3 executable does not exist: ${GXBUILD3_EXE}")
endif()
if(NOT DEFINED GXBUILD3_FIXTURE_GENERATOR OR GXBUILD3_FIXTURE_GENERATOR STREQUAL "")
    message(FATAL_ERROR "GXBUILD3_FIXTURE_GENERATOR must name the CLI integration fixture generator")
endif()
if(NOT EXISTS "${GXBUILD3_FIXTURE_GENERATOR}")
    message(FATAL_ERROR "CLI integration fixture generator does not exist: ${GXBUILD3_FIXTURE_GENERATOR}")
endif()
if(NOT DEFINED GXBUILD3_OUTPUT_VERIFIER OR GXBUILD3_OUTPUT_VERIFIER STREQUAL "")
    message(FATAL_ERROR "GXBUILD3_OUTPUT_VERIFIER must name the CLI output verifier")
endif()
if(NOT EXISTS "${GXBUILD3_OUTPUT_VERIFIER}")
    message(FATAL_ERROR "CLI output verifier does not exist: ${GXBUILD3_OUTPUT_VERIFIER}")
endif()
if(NOT DEFINED TEST_ROOT OR TEST_ROOT STREQUAL "")
    message(FATAL_ERROR "TEST_ROOT must name a writable test-fixture directory")
endif()

get_filename_component(gxbuild_executable_name "${GXBUILD3_EXE}" NAME_WE)
if(NOT gxbuild_executable_name STREQUAL "gxbuild")
    message(FATAL_ERROR "the installed CLI artifact must be named gxbuild, got '${gxbuild_executable_name}'")
endif()

function(require_result name actual expected)
    if(NOT "${actual}" STREQUAL "${expected}")
        message(FATAL_ERROR "${name}: expected exit ${expected}, got ${actual}")
    endif()
endfunction()

function(verify_output name output_path)
    execute_process(
        COMMAND "${GXBUILD3_OUTPUT_VERIFIER}" "${output_path}"
        RESULT_VARIABLE verifier_result
        OUTPUT_VARIABLE verifier_output
        ERROR_VARIABLE verifier_error)
    if(NOT verifier_result EQUAL 0)
        message(FATAL_ERROR
            "${name}: output verifier failed with exit ${verifier_result}\n"
            "stdout: ${verifier_output}\n"
            "stderr: ${verifier_error}")
    endif()
endfunction()

file(REMOVE_RECURSE "${TEST_ROOT}")
file(MAKE_DIRECTORY "${TEST_ROOT}")
execute_process(
    COMMAND "${GXBUILD3_FIXTURE_GENERATOR}" "${TEST_ROOT}"
    RESULT_VARIABLE fixture_result
    OUTPUT_VARIABLE fixture_output
    ERROR_VARIABLE fixture_error)
require_result("CLI fixture generator" "${fixture_result}" "0")
if(NOT fixture_error STREQUAL "")
    message(FATAL_ERROR "CLI fixture generator must not write to stderr: ${fixture_error}")
endif()

file(TO_CMAKE_PATH "${TEST_ROOT}/source" WINDOWS_SOURCE_DIR)
if(NOT WINDOWS_SOURCE_DIR MATCHES "^[A-Za-z]:/")
    message(FATAL_ERROR "The CLI integration fixture must use a Windows drive path")
endif()

execute_process(
    COMMAND "${GXBUILD3_EXE}" --help
    RESULT_VARIABLE help_result
    OUTPUT_VARIABLE help_output
    ERROR_VARIABLE help_error)
require_result("--help" "${help_result}" "0")
if(NOT help_output MATCHES "Usage: gxbuild \\[build\\] \\[options\\]" OR
   NOT help_output MATCHES "Required build options" OR NOT help_error STREQUAL "")
    message(FATAL_ERROR "--help must render the gxbuild build usage on stdout only")
endif()

execute_process(
    COMMAND "${GXBUILD3_EXE}" --version
    RESULT_VARIABLE version_result
    OUTPUT_VARIABLE version_output
    ERROR_VARIABLE version_error)
require_result("--version" "${version_result}" "0")
if(NOT version_output MATCHES "^gxbuild [0-9]+\\.[0-9]+\\.[0-9]+" OR
   NOT version_error STREQUAL "")
    message(FATAL_ERROR "--version must identify gxbuild on stdout only")
endif()

execute_process(
    COMMAND "${GXBUILD3_EXE}" build
    RESULT_VARIABLE missing_arguments_result
    OUTPUT_VARIABLE missing_arguments_output
    ERROR_VARIABLE missing_arguments_error)
require_result("missing required arguments" "${missing_arguments_result}" "2")
if(NOT missing_arguments_error MATCHES "^gxbuild: missing required build INI" OR
   NOT missing_arguments_output STREQUAL "")
    message(FATAL_ERROR "missing required arguments must be a command-line error on stderr")
endif()

execute_process(
    COMMAND "${GXBUILD3_EXE}" -b "${TEST_ROOT}/build.ini" -s falcon -t retail:xsb
            -d "${WINDOWS_SOURCE_DIR}"
    RESULT_VARIABLE missing_cpu_result
    OUTPUT_VARIABLE missing_cpu_output
    ERROR_VARIABLE missing_cpu_error)
require_result("missing CPU key" "${missing_cpu_result}" "3")
if(NOT missing_cpu_error MATCHES "^gxbuild: No CPU key was supplied" OR
   NOT missing_cpu_output STREQUAL "")
    message(FATAL_ERROR
        "a Windows drive source path must remain one source directory and reach CPU-key resolution")
endif()

execute_process(
    COMMAND "${GXBUILD3_EXE}" -b "${TEST_ROOT}/build.ini" -s falcon -t retail:xsb
            -d "${WINDOWS_SOURCE_DIR}" -p ffffffffffff1f0000000000006ce58d
            -i "${TEST_ROOT}/missing-nanddump.bin"
    RESULT_VARIABLE missing_donor_result
    OUTPUT_VARIABLE missing_donor_output
    ERROR_VARIABLE missing_donor_error)
require_result("missing donor data" "${missing_donor_result}" "3")
if(NOT missing_donor_error MATCHES "^gxbuild: Could not read explicit donor NAND" OR
   NOT missing_donor_output STREQUAL "")
    message(FATAL_ERROR "missing donor data must be an input-resolution error on stderr")
endif()

execute_process(
    COMMAND "${GXBUILD3_EXE}" -x
    RESULT_VARIABLE xebuild_result
    OUTPUT_VARIABLE xebuild_output
    ERROR_VARIABLE xebuild_error)
require_result("unsupported -x mode" "${xebuild_result}" "2")
if(NOT xebuild_error MATCHES "^gxbuild: unknown argument '-x'" OR
   NOT xebuild_output STREQUAL "")
    message(FATAL_ERROR "unsupported -x mode must identify -x as a command-line error")
endif()

set(fixture_cpu_key "ffffffffffff1f0000000000006ce58d")
set(fixture_build_arguments
    -b "${TEST_ROOT}/build.ini"
    -s falcon
    -t retail:xsb
    -d "${WINDOWS_SOURCE_DIR}"
    -p "${fixture_cpu_key}"
    -i "${TEST_ROOT}/donor-nand.bin")
set(default_output "${TEST_ROOT}/updflash.bin")

execute_process(
    COMMAND "${GXBUILD3_EXE}" ${fixture_build_arguments}
    WORKING_DIRECTORY "${TEST_ROOT}"
    RESULT_VARIABLE default_build_result
    OUTPUT_VARIABLE default_build_output
    ERROR_VARIABLE default_build_error)
require_result("default-output real build" "${default_build_result}" "0")
verify_output("default-output real build" "${default_output}")
if(NOT EXISTS "${default_output}")
    message(FATAL_ERROR "a successful build must write updflash.bin in its working directory")
endif()
file(SIZE "${default_output}" default_output_size)
if(NOT default_output_size EQUAL 17301504)
    message(FATAL_ERROR "the default output must be a valid-sized NAND image, got ${default_output_size}")
endif()

file(WRITE "${default_output}" "stale output")
execute_process(
    COMMAND "${GXBUILD3_EXE}" ${fixture_build_arguments}
    WORKING_DIRECTORY "${TEST_ROOT}"
    RESULT_VARIABLE overwrite_build_result
    OUTPUT_VARIABLE overwrite_build_output
    ERROR_VARIABLE overwrite_build_error)
require_result("default-output overwrite build" "${overwrite_build_result}" "0")
verify_output("default-output overwrite build" "${default_output}")
file(SIZE "${default_output}" overwritten_output_size)
if(NOT overwritten_output_size EQUAL 17301504)
    message(FATAL_ERROR "a second build must overwrite the existing default output")
endif()

set(nested_output "${TEST_ROOT}/nested/output/updflash.bin")
execute_process(
    COMMAND "${GXBUILD3_EXE}" ${fixture_build_arguments} -o "${nested_output}"
    WORKING_DIRECTORY "${TEST_ROOT}"
    RESULT_VARIABLE nested_build_result
    OUTPUT_VARIABLE nested_build_output
    ERROR_VARIABLE nested_build_error)
require_result("nested-output real build" "${nested_build_result}" "0")
verify_output("nested-output real build" "${nested_output}")
if(NOT EXISTS "${nested_output}")
    message(FATAL_ERROR "an explicit nested output path must be created")
endif()
file(SIZE "${nested_output}" nested_output_size)
if(NOT nested_output_size EQUAL 17301504)
    message(FATAL_ERROR "the nested output must be a valid-sized NAND image, got ${nested_output_size}")
endif()

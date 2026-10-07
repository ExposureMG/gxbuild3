# gxbuild3 tests, registered only when GXBUILD3_BUILD_TESTS and BUILD_TESTING are on (see the
# root CMakeLists.txt). Source paths are relative to tests/; the fixed scratch directories
# (flashimage-tests, cli-integration-tests) stay under CMAKE_BINARY_DIR.
# CMake -P tests live in scripts/, helper executables that are not tests in tools/.
#
# Labels: unit (plain test binaries), golden (text-golden binaries), oracle (the build_all.sh
# byte oracle), guard (convention, test-listing, coverage-ledger, golden-freeze and self-test
# scripts), integration and cli (the CLI end-to-end script), private (needs the git-ignored
# keyvault fixtures), slow (minutes, not seconds).
# GoogleTest binaries (gxbuild3_add_gtest, one fragment per area in <area>/Tests.cmake) add
# their area label (core, ...) and register ctest entries named <area prefix>.<gtest name>.
# Every test runs with TMPDIR=<build>/tmp: /tmp is often a small shared tmpfs.

set(GXBUILD3_TEST_SCRIPTS ${CMAKE_CURRENT_SOURCE_DIR}/scripts)
set(GXBUILD3_TEST_TMPDIR ${CMAKE_BINARY_DIR}/tmp)
file(MAKE_DIRECTORY ${GXBUILD3_TEST_TMPDIR})

# Common setup of every test executable and tool: internal headers, tests/ for the shared
# test headers, -Werror warnings and no C++20 module scanning.
function(gxbuild3_test_target target)
    target_link_libraries(${target} PRIVATE gxbuild3_internal)
    target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/tests)
    set_target_properties(${target} PROPERTIES CXX_SCAN_FOR_MODULES OFF)
    gxbuild3_enable_warnings(${target})
endfunction()

# add_gxbuild3_test(<name> <source> [LABELS <label>...]); LABELS defaults to unit.
function(add_gxbuild3_test name source)
    cmake_parse_arguments(T "" "" "LABELS" ${ARGN})
    if(NOT T_LABELS)
        set(T_LABELS unit)
    endif()
    add_executable(${name} ${source})
    gxbuild3_test_target(${name})
    # Tracked text goldens for support/golden/GoldenSnapshot.hpp, which the old binaries still
    # include as "GoldenSnapshot.hpp". CTest never passes --update.
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/support/golden)
    target_compile_definitions(${name} PRIVATE
        GXBUILD3_GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/golden")
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS "${T_LABELS}")
endfunction()

# ---- GoogleTest ------------------------------------------------------------------------------
# The installed package (pacman gtest, brew googletest, vcpkg gtest); its imported targets are
# SYSTEM, so -Werror does not reach its headers. 1.17 brings --gtest_fail_if_no_test_selected.
find_package(GTest 1.17 CONFIG REQUIRED)
include(GoogleTest)

set(GXBUILD3_TEST_SCRATCH_ROOT ${CMAKE_BINARY_DIR}/test-scratch)
file(MAKE_DIRECTORY ${GXBUILD3_TEST_SCRATCH_ROOT})

# gxbuild3::test support library: Result-aware assertions, scratch directories, scoped
# environment, byte helpers and the test CPU keys. Tests include it as "support/<Name>.hpp".
add_library(gxbuild3_test_support STATIC
    support/Bytes.cpp
    support/Expect.cpp
    support/Keys.cpp
    support/Scratch.cpp)
target_include_directories(gxbuild3_test_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gxbuild3_test_support PUBLIC gxbuild3_internal GTest::gtest)
target_compile_definitions(gxbuild3_test_support PUBLIC
    GXBUILD3_GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/golden"
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files"
    GXBUILD3_TEST_SCRATCH_ROOT="${GXBUILD3_TEST_SCRATCH_ROOT}")
set_target_properties(gxbuild3_test_support PROPERTIES CXX_SCAN_FOR_MODULES OFF)
gxbuild3_enable_warnings(gxbuild3_test_support)

# gxbuild3_flashimage_render: the FlashImage text renderers (support/render/FlashImageRender.hpp)
# shared by the FlashImage goldens and the oracle's snapshot tool. No GoogleTest, so the tool
# stays a plain executable. support/render/ExtractProjection.hpp is header-only beside it.
add_library(gxbuild3_flashimage_render STATIC
    support/render/FlashImageRender.cpp
    support/render/FlashImageRenderWrite.cpp)
target_include_directories(gxbuild3_flashimage_render PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gxbuild3_flashimage_render PUBLIC gxbuild3_internal)
set_target_properties(gxbuild3_flashimage_render PROPERTIES CXX_SCAN_FOR_MODULES OFF)
gxbuild3_enable_warnings(gxbuild3_flashimage_render)

# Standard and gtest headers only, never src/ headers.
set(GXBUILD3_GTEST_PCH
    <gtest/gtest.h> <algorithm> <array> <cstdint> <expected> <filesystem> <format>
    <optional> <span> <string> <string_view> <vector>)

# gxbuild3_add_gtest(<name> PREFIX <prefix> LABELS <label>... SOURCES <file>...
#                    [LIBS <target>...] [MAIN <file>] [TIMEOUT <seconds>]
#                    [BUNDLE <Suite|Inst/Suite>...] [PER_ROW <Inst/Suite>...]
#                    [SKIP_BUNDLE <bundle>...])
#
# One GoogleTest executable. Every case is its own ctest entry, <prefix>.<Suite>.<Test>,
# discovered before each ctest run (PRE_TEST, so building never runs test code), except:
#  - BUNDLE: each entry is ONE ctest entry, <prefix>.<entry>, that runs the whole suite
#    (<entry>.* and its instantiations */<entry>.*) or one instantiation (Inst/Suite.*) with
#    --gtest_fail_if_no_test_selected, so a stale bundle name fails. Bundled cases are filtered
#    out of discovery, so no case is registered twice; a failing row prints its full gtest name
#    and the other rows still run.
#  - SKIP_BUNDLE: bundles (also listed under BUNDLE) whose cases may GTEST_SKIP; ctest reports
#    them as skipped. Other bundles never skip.
#  - PER_ROW: TEST_P instantiations whose rows are each slow enough to be their own entry; they
#    are discovered per row like any unbundled case and only recorded for the guards.
# Each binary adds a line `name|prefix|path|bundles|per_row|skip_bundles` (lists
# comma-separated) to <build>/tests/gtest-binaries.txt, which the listing and ledger guards read.
function(gxbuild3_add_gtest name)
    cmake_parse_arguments(T "" "PREFIX;TIMEOUT;MAIN" "SOURCES;LABELS;LIBS;BUNDLE;PER_ROW;SKIP_BUNDLE"
        ${ARGN})
    if(NOT T_PREFIX OR NOT T_LABELS OR NOT T_SOURCES)
        message(FATAL_ERROR "gxbuild3_add_gtest(${name}) needs PREFIX, LABELS and SOURCES")
    endif()
    if(T_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "gxbuild3_add_gtest(${name}): unknown arguments ${T_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT T_TIMEOUT)
        set(T_TIMEOUT 120)
    endif()

    add_executable(${name} ${T_SOURCES})
    if(T_MAIN)
        target_sources(${name} PRIVATE ${T_MAIN})
    else()
        target_link_libraries(${name} PRIVATE GTest::gtest_main)
    endif()
    target_link_libraries(${name} PRIVATE gxbuild3_test_support ${T_LIBS})
    target_precompile_headers(${name} PRIVATE ${GXBUILD3_GTEST_PCH})
    set_target_properties(${name} PROPERTIES CXX_SCAN_FOR_MODULES OFF)
    gxbuild3_enable_warnings(${name})

    foreach(skip IN LISTS T_SKIP_BUNDLE)
        if(NOT skip IN_LIST T_BUNDLE)
            message(FATAL_ERROR "gxbuild3_add_gtest(${name}): SKIP_BUNDLE ${skip} is not a BUNDLE")
        endif()
    endforeach()
    foreach(row IN LISTS T_PER_ROW)
        if(NOT row MATCHES "^[A-Za-z0-9_]+/[A-Za-z0-9_]+$" OR row IN_LIST T_BUNDLE)
            message(FATAL_ERROR
                "gxbuild3_add_gtest(${name}): PER_ROW ${row} must be an unbundled Inst/Suite")
        endif()
    endforeach()

    set(excluded "")
    foreach(bundle IN LISTS T_BUNDLE)
        if(bundle MATCHES "^[A-Za-z0-9_]+/[A-Za-z0-9_]+$")
            set(pattern "${bundle}.*")
        elseif(bundle MATCHES "^[A-Za-z0-9_]+$")
            set(pattern "${bundle}.*:*/${bundle}.*")
        else()
            message(FATAL_ERROR "gxbuild3_add_gtest(${name}): bad BUNDLE ${bundle}")
        endif()
        list(APPEND excluded "${pattern}")
        add_test(NAME ${T_PREFIX}.${bundle}
            COMMAND ${name} --gtest_filter=${pattern} --gtest_fail_if_no_test_selected)
        set_tests_properties(${T_PREFIX}.${bundle} PROPERTIES
            LABELS "${T_LABELS}" TIMEOUT ${T_TIMEOUT}
            ENVIRONMENT "TMPDIR=${GXBUILD3_TEST_TMPDIR}")
        if(bundle IN_LIST T_SKIP_BUNDLE)
            set_tests_properties(${T_PREFIX}.${bundle} PROPERTIES
                SKIP_REGULAR_EXPRESSION "\\[  SKIPPED \\]")
        endif()
    endforeach()

    set(filter "")
    if(excluded)
        list(JOIN excluded ":" negative)
        set(filter TEST_FILTER "-${negative}")
    endif()
    gtest_discover_tests(${name}
        DISCOVERY_MODE PRE_TEST
        TEST_PREFIX "${T_PREFIX}."
        ${filter}
        PROPERTIES LABELS "${T_LABELS}" TIMEOUT ${T_TIMEOUT}
                   ENVIRONMENT "TMPDIR=${GXBUILD3_TEST_TMPDIR}")

    list(JOIN T_BUNDLE "," bundles)
    list(JOIN T_PER_ROW "," per_row)
    list(JOIN T_SKIP_BUNDLE "," skip_bundles)
    set_property(GLOBAL APPEND PROPERTY GXBUILD3_GTEST_BINARIES
        "${name}|${T_PREFIX}|$<TARGET_FILE:${name}>|${bundles}|${per_row}|${skip_bundles}")
endfunction()

# One fragment per area: its gxbuild3_add_gtest call with the area's BUNDLE and PER_ROW lists.
include(core/Tests.cmake)
include(utils/Tests.cmake)
include(stfs/Tests.cmake)
include(bootloaders/Tests.cmake)
include(objects/Tests.cmake)
include(snapshots/Tests.cmake)
include(private/Tests.cmake)

# ---- Pre-GoogleTest test executables (ported area by area, then deleted) --------------------

add_gxbuild3_test(gxbuild3_anchor_layout_tests AnchorLayoutTests.cpp)
add_gxbuild3_test(gxbuild3_flashdriver_tests FlashDriverTests.cpp)
add_gxbuild3_test(gxbuild3_flashfs_tests FlashFileSystemTests.cpp)
add_gxbuild3_test(gxbuild3_commandline_tests CommandLineTests.cpp)
add_gxbuild3_test(gxbuild3_buildrunner_tests BuildRunnerTests.cpp)
add_gxbuild3_test(gxbuild3_glitch_crypto_tests GlitchCryptoTests.cpp)
add_gxbuild3_test(gxbuild3_resolver_tests BuildInputResolverTests.cpp)
add_gxbuild3_test(gxbuild3_buildcommand_tests BuildCommandTests.cpp)
add_gxbuild3_test(gxbuild3_crypto_reference_tests CryptoReferenceTests.cpp)
# src/nand/bootloaders/Stage.hpp: the shared stage parse, padding, serialize and record crypt
# checked against a plain crypt_single_bl, plus the paths the bootloader corpus never reaches.
add_gxbuild3_test(gxbuild3_stage_tests StageTests.cpp)
# tests/TestResult.hpp's must() aborts with Error::describe() and the call site; the demo tool
# fails it on purpose (retired with must()).
add_executable(gxbuild3_must_abort_demo tools/MustAbortDemo.cpp)
gxbuild3_test_target(gxbuild3_must_abort_demo)
add_test(NAME gxbuild3_must_abort_tests
    COMMAND ${CMAKE_COMMAND}
        -DGXBUILD3_SELFTEST=$<TARGET_FILE:gxbuild3_must_abort_demo>
        -P ${GXBUILD3_TEST_SCRIPTS}/MustAbortTest.cmake)
set_tests_properties(gxbuild3_must_abort_tests PROPERTIES LABELS guard)
foreach(cli_test gxbuild3_commandline_tests gxbuild3_resolver_tests
        gxbuild3_buildcommand_tests)
    target_link_libraries(${cli_test} PRIVATE gxbuild3_cli)
endforeach()
target_compile_definitions(gxbuild3_crypto_reference_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
# In-process goldens over the tracked mydata/image.bin (tests/golden/flashimage_golden.txt),
# the synthetic fresh-layout matrix (flashimage_matrix.txt) and the FlashImage failure
# table (flashimage_failures.txt). The matrix writes 48 full-size images: about 30 s in
# Release, so the timeout leaves room for an unoptimized build.
add_gxbuild3_test(gxbuild3_flashimage_golden_tests FlashImageGoldenTests.cpp LABELS golden)
target_link_libraries(gxbuild3_flashimage_golden_tests PRIVATE gxbuild3_flashimage_render)
target_compile_definitions(gxbuild3_flashimage_golden_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
set_tests_properties(gxbuild3_flashimage_golden_tests PROPERTIES TIMEOUT 600)
# Snapshot of every tracked bootloader stage fixture in common/*.bin
# (tests/golden/wire_corpus_bootloaders.txt): parse fields, serialize identity, per-box
# bytes and seals under fixed keys, with all-zero nonces pinned inside the test.
add_gxbuild3_test(gxbuild3_wire_corpus_tests WireCorpusTests.cpp LABELS golden)
target_compile_definitions(gxbuild3_wire_corpus_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
# Snapshot of the NAND-object codecs over tracked fixtures (tests/golden/objects_corpus.txt):
# every patches_*.bin x build type with and without add-ons, XeLL, the mydata secured files,
# xboxupd.bin from su20076000, CoronaConfig, freeBOOT, XConfig and the SMC classifier.
add_gxbuild3_test(gxbuild3_objects_corpus_tests ObjectsCorpusTests.cpp LABELS golden)
target_compile_definitions(gxbuild3_objects_corpus_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
# run_build digests over the tracked mydata/image.bin (tests/golden/
# orchestration_mydata_builds.txt): extract_all, then retail, jtag and glitch2 rebuilds with
# the tracked patch files and XeLLs, each built twice under a pinned time and donor nonces;
# then every public extract_* projection of image.bin and of the glitch2 rebuild
# (tests/golden/extract_projections_mydata.txt, via tests/support/render/ExtractProjection.hpp).
add_gxbuild3_test(gxbuild3_orchestration_golden_tests OrchestrationGoldenTests.cpp LABELS golden)
target_compile_definitions(gxbuild3_orchestration_golden_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
set_tests_properties(gxbuild3_orchestration_golden_tests PROPERTIES TIMEOUT 300)

# The byte oracle's snapshot tool: --snapshot <image> [--expect <file>], exit 0/1/2.
add_executable(gxbuild3_flashimage_snapshot tools/FlashImageSnapshot.cpp)
gxbuild3_test_target(gxbuild3_flashimage_snapshot)
target_link_libraries(gxbuild3_flashimage_snapshot PRIVATE gxbuild3_flashimage_render)

# Keeps the snapshot tool exercised on a clean clone, where the oracle skips: it must snapshot
# the tracked mydata/image.bin, agree with its own output through --expect, report a perturbed
# expectation (exit 1) and refuse a missing or unknown argument (exit 2).
add_test(NAME gxbuild3_flashimage_snapshot_smoke
    COMMAND ${CMAKE_COMMAND}
        -DGXBUILD3_SNAPSHOT_TOOL=$<TARGET_FILE:gxbuild3_flashimage_snapshot>
        -DGXBUILD3_IMAGE=${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files/mydata/image.bin
        -DGXBUILD3_SCRATCH_DIR=${GXBUILD3_TEST_SCRATCH_ROOT}/flashimage-snapshot-smoke
        -P ${GXBUILD3_TEST_SCRIPTS}/FlashImageSnapshotSmoke.cmake)
set_tests_properties(gxbuild3_flashimage_snapshot_smoke PROPERTIES LABELS golden)

add_executable(gxbuild3_cli_fixture_generator tools/CliFixtureGenerator.cpp)
gxbuild3_test_target(gxbuild3_cli_fixture_generator)

add_executable(gxbuild3_cli_output_verifier tools/CliOutputVerifier.cpp)
gxbuild3_test_target(gxbuild3_cli_output_verifier)

add_test(NAME gxbuild3_cli_integration_tests
    COMMAND ${CMAKE_COMMAND}
        -DGXBUILD3_EXE=$<TARGET_FILE:gxbuild3>
        -DGXBUILD3_FIXTURE_GENERATOR=$<TARGET_FILE:gxbuild3_cli_fixture_generator>
        -DGXBUILD3_OUTPUT_VERIFIER=$<TARGET_FILE:gxbuild3_cli_output_verifier>
        -DTEST_ROOT=${CMAKE_BINARY_DIR}/cli-integration-tests
        -P ${GXBUILD3_TEST_SCRIPTS}/CliIntegrationTests.cmake)
set_tests_properties(gxbuild3_cli_integration_tests PROPERTIES LABELS "integration;cli")

add_test(NAME gxbuild3_error_convention_guard
    COMMAND ${CMAKE_COMMAND}
        -DSOURCE_ROOT=${PROJECT_SOURCE_DIR}
        -P ${GXBUILD3_TEST_SCRIPTS}/ErrorConventionGuard.cmake)
set_tests_properties(gxbuild3_error_convention_guard PROPERTIES LABELS guard)

find_program(GXBUILD3_BASH_EXECUTABLE NAMES bash)
if(UNIX)
    # Byte oracle over build_all.sh against tests/golden/build_all.sha256, plus the
    # parse snapshot of every image it writes against tests/golden/build_all.parse.txt
    # (gxbuild3_flashimage_snapshot --snapshot). The capture target below is the
    # only way to rewrite either golden; CTest never passes GXBUILD3_UPDATE_GOLDEN.
    set(GXBUILD3_FLASHIMAGE_ARGS
        -DGXBUILD3_EXE=$<TARGET_FILE:gxbuild3>
        -DGXBUILD3_SUPPORT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files
        -DGXBUILD3_BASH=${GXBUILD3_BASH_EXECUTABLE}
        -DGXBUILD3_GOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/golden/build_all.sha256
        -DGXBUILD3_SNAPSHOT_TOOL=$<TARGET_FILE:gxbuild3_flashimage_snapshot>
        -DGXBUILD3_PARSE_GOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/golden/build_all.parse.txt
        -DGXBUILD3_SCRATCH_DIR=${CMAKE_BINARY_DIR}/flashimage-tests)
    add_test(NAME gxbuild3_flashimage_tests
        COMMAND ${CMAKE_COMMAND} ${GXBUILD3_FLASHIMAGE_ARGS}
            -P ${GXBUILD3_TEST_SCRIPTS}/FlashImageTests.cmake)
    # COST 1000 makes ctest start the longest test first under -j.
    set_tests_properties(gxbuild3_flashimage_tests PROPERTIES
        TIMEOUT 1800 SKIP_RETURN_CODE 77 COST 1000 LABELS "oracle;golden;slow")
    add_custom_target(gxbuild3_flashimage_golden_update
        COMMAND ${CMAKE_COMMAND} ${GXBUILD3_FLASHIMAGE_ARGS} -DGXBUILD3_UPDATE_GOLDEN=1
            -P ${GXBUILD3_TEST_SCRIPTS}/FlashImageTests.cmake
        DEPENDS gxbuild3 gxbuild3_flashimage_snapshot
        USES_TERMINAL
        COMMENT "Capturing tests/golden/build_all.sha256 and build_all.parse.txt (two identical runs required)")
endif()

# The GoogleTest binary registry for the guards below:
# name|prefix|path|bundles|per_row|skip_bundles.
get_property(gxbuild3_gtest_binaries GLOBAL PROPERTY GXBUILD3_GTEST_BINARIES)
list(JOIN gxbuild3_gtest_binaries "\n" gxbuild3_gtest_listing)
if(CMAKE_CONFIGURATION_TYPES)
    set(gxbuild3_gtest_listing_file ${CMAKE_CURRENT_BINARY_DIR}/gtest-binaries-$<CONFIG>.txt)
else()
    set(gxbuild3_gtest_listing_file ${CMAKE_CURRENT_BINARY_DIR}/gtest-binaries.txt)
endif()
file(GENERATE OUTPUT ${gxbuild3_gtest_listing_file} CONTENT "${gxbuild3_gtest_listing}\n")

# Permanent: every listed case runs in exactly one ctest entry, bundles are live, TEST_P rows
# are named and only PER_ROW tables are discovered per row, no skip hides in a bundle, no
# captured stream or death test (scripts/TestListingGuard.cmake).
add_test(NAME gxbuild3_test_listing_guard
    COMMAND ${CMAKE_COMMAND}
        -DGTEST_BINARIES=${gxbuild3_gtest_listing_file}
        -DCTEST_COMMAND=${CMAKE_CTEST_COMMAND}
        -DBUILD_DIR=${CMAKE_BINARY_DIR}
        -DCONFIG=$<CONFIG>
        -DTESTS_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DGOLDEN_DIR=${CMAKE_CURRENT_SOURCE_DIR}/golden
        -P ${GXBUILD3_TEST_SCRIPTS}/TestListingGuard.cmake)

# Migration only, deleted with tests/migration/: the coverage ledger (one row per old test
# function, static_assert and table row; scripts/CoverageLedger.cmake, seeded once by
# scripts/SeedLedger.cmake) and the frozen goldens (scripts/GoldenFrozen.cmake).
add_test(NAME gxbuild3_coverage_ledger
    COMMAND ${CMAKE_COMMAND}
        -DSOURCE_ROOT=${PROJECT_SOURCE_DIR}
        -DGTEST_BINARIES=${gxbuild3_gtest_listing_file}
        -P ${GXBUILD3_TEST_SCRIPTS}/CoverageLedger.cmake)
add_test(NAME gxbuild3_golden_frozen
    COMMAND ${CMAKE_COMMAND}
        -DGOLDEN_DIR=${CMAKE_CURRENT_SOURCE_DIR}/golden
        -DBASELINE=${CMAKE_CURRENT_SOURCE_DIR}/migration/golden-baseline.sha256
        -P ${GXBUILD3_TEST_SCRIPTS}/GoldenFrozen.cmake)
set_tests_properties(gxbuild3_test_listing_guard gxbuild3_coverage_ledger gxbuild3_golden_frozen
    PROPERTIES LABELS guard)

get_property(gxbuild3_registered_tests DIRECTORY PROPERTY TESTS)
set_tests_properties(${gxbuild3_registered_tests} PROPERTIES
    ENVIRONMENT "TMPDIR=${GXBUILD3_TEST_TMPDIR}")

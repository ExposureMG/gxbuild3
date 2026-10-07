# gxbuild3 tests, registered only when GXBUILD3_BUILD_TESTS and BUILD_TESTING are on (see the
# root CMakeLists.txt). Source paths are relative to tests/; the fixed scratch directories
# (flashimage-tests, cli-integration-tests, golden-snapshot-tests) stay under CMAKE_BINARY_DIR.

function(add_gxbuild3_test name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE gxbuild3_internal)
    gxbuild3_enable_warnings(${name})
    # Tracked text goldens for tests/GoldenSnapshot.hpp. CTest never passes --update.
    target_compile_definitions(${name} PRIVATE
        GXBUILD3_GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/golden")
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_gxbuild3_test(gxbuild3_anchor_layout_tests AnchorLayoutTests.cpp)
add_gxbuild3_test(gxbuild3_flashdriver_tests FlashDriverTests.cpp)
add_gxbuild3_test(gxbuild3_flashfs_tests FlashFileSystemTests.cpp)
add_gxbuild3_test(gxbuild3_build_time_tests BuildTimeTests.cpp)
add_gxbuild3_test(gxbuild3_secured_files_tests SecuredFilesTests.cpp)
add_gxbuild3_test(gxbuild3_filemanager_tests FileManagerTests.cpp)
add_gxbuild3_test(gxbuild3_input_tests InputTests.cpp)
add_gxbuild3_test(gxbuild3_commandline_tests CommandLineTests.cpp)
add_gxbuild3_test(gxbuild3_buildrunner_tests BuildRunnerTests.cpp)
add_gxbuild3_test(gxbuild3_patchset_tests PatchsetTests.cpp)
add_gxbuild3_test(gxbuild3_patcher_tests PatcherTests.cpp)
add_gxbuild3_test(gxbuild3_glitch_crypto_tests GlitchCryptoTests.cpp)
add_gxbuild3_test(gxbuild3_resolver_tests BuildInputResolverTests.cpp)
add_gxbuild3_test(gxbuild3_fuseset_tests FusesetGeneratorTests.cpp)
add_gxbuild3_test(gxbuild3_buildcommand_tests BuildCommandTests.cpp)
add_gxbuild3_test(gxbuild3_keyvault_version_tests KeyvaultVersionTests.cpp)
add_gxbuild3_test(gxbuild3_xe_rsa_tests XeRsaTests.cpp)
add_gxbuild3_test(gxbuild3_crypto_reference_tests CryptoReferenceTests.cpp)
add_gxbuild3_test(gxbuild3_stfs_tests StfsTests.cpp)
add_gxbuild3_test(gxbuild3_error_tests ErrorTests.cpp)
# src/Wire.hpp: endian field types, record codecs, Cursor, the compile-time rejections
# (deleted swaps, no compound assignment) and formatting through std::format and Log.hpp.
add_gxbuild3_test(gxbuild3_wire_tests WireTests.cpp)
# Compile-time sizeof/offsetof pins of every bootloader record in Common.hpp, taken from
# the on-disk layout; the run prints how many records and fields the build pinned.
add_gxbuild3_test(gxbuild3_bootloader_layout_tests BootloaderLayoutTests.cpp)
# src/nand/bootloaders/Stage.hpp: the shared stage parse, padding, serialize and record crypt
# checked against a plain crypt_single_bl, plus the paths the bootloader corpus never reaches.
add_gxbuild3_test(gxbuild3_stage_tests StageTests.cpp)
add_gxbuild3_test(gxbuild3_golden_snapshot_tests GoldenSnapshotTests.cpp)
target_compile_definitions(gxbuild3_golden_snapshot_tests PRIVATE
    GXBUILD3_TEST_SCRATCH_DIR="${CMAKE_BINARY_DIR}/golden-snapshot-tests")
add_test(NAME gxbuild3_must_abort_tests
    COMMAND ${CMAKE_COMMAND}
        -DGXBUILD3_SELFTEST=$<TARGET_FILE:gxbuild3_golden_snapshot_tests>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/MustAbortTest.cmake)
foreach(cli_test gxbuild3_commandline_tests gxbuild3_resolver_tests
        gxbuild3_buildcommand_tests)
    target_link_libraries(${cli_test} PRIVATE gxbuild3_cli)
endforeach()
target_compile_definitions(gxbuild3_stfs_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
set_tests_properties(gxbuild3_stfs_tests PROPERTIES TIMEOUT 60)
target_compile_definitions(gxbuild3_crypto_reference_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
# In-process goldens over the tracked mydata/image.bin (tests/golden/flashimage_golden.txt),
# the synthetic fresh-layout matrix (flashimage_matrix.txt) and the FlashImage failure
# table (flashimage_failures.txt). The matrix writes 48 full-size images: about 30 s in
# Release, so the timeout leaves room for an unoptimized build.
add_gxbuild3_test(gxbuild3_flashimage_golden_tests FlashImageGoldenTests.cpp)
target_compile_definitions(gxbuild3_flashimage_golden_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
set_tests_properties(gxbuild3_flashimage_golden_tests PROPERTIES TIMEOUT 600)
# Snapshot of every tracked bootloader stage fixture in common/*.bin
# (tests/golden/wire_corpus_bootloaders.txt): parse fields, serialize identity, per-box
# bytes and seals under fixed keys, with all-zero nonces pinned inside the test.
add_gxbuild3_test(gxbuild3_wire_corpus_tests WireCorpusTests.cpp)
target_compile_definitions(gxbuild3_wire_corpus_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
# Snapshot of the NAND-object codecs over tracked fixtures (tests/golden/objects_corpus.txt):
# every patches_*.bin x build type with and without add-ons, XeLL, the mydata secured files,
# xboxupd.bin from su20076000, CoronaConfig, freeBOOT, XConfig and the SMC classifier.
add_gxbuild3_test(gxbuild3_objects_corpus_tests ObjectsCorpusTests.cpp)
target_compile_definitions(gxbuild3_objects_corpus_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
# run_build digests over the tracked mydata/image.bin (tests/golden/
# orchestration_mydata_builds.txt): extract_all, then retail, jtag and glitch2 rebuilds with
# the tracked patch files and XeLLs, each built twice under a pinned time and donor nonces;
# then every public extract_* projection of image.bin and of the glitch2 rebuild
# (tests/golden/extract_projections_mydata.txt, via tests/ExtractProjection.hpp).
add_gxbuild3_test(gxbuild3_orchestration_golden_tests OrchestrationGoldenTests.cpp)
target_compile_definitions(gxbuild3_orchestration_golden_tests PRIVATE
    GXBUILD3_SUPPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files")
set_tests_properties(gxbuild3_orchestration_golden_tests PROPERTIES TIMEOUT 300)

add_executable(gxbuild3_keyvault_crypto_tests KeyvaultCryptoTests.cpp)
target_link_libraries(gxbuild3_keyvault_crypto_tests PRIVATE gxbuild3_internal)
gxbuild3_enable_warnings(gxbuild3_keyvault_crypto_tests)
set(GXBUILD3_KEYVAULT_CPU_KEY_FILE "${PROJECT_SOURCE_DIR}/_temp/cpukey.txt"
    CACHE FILEPATH "Private CPU key fixture (32 hex characters)")
set(GXBUILD3_KEYVAULT_ENCRYPTED_FILE "${PROJECT_SOURCE_DIR}/_temp/KV_en.bin"
    CACHE FILEPATH "Private encrypted keyvault fixture")
set(GXBUILD3_KEYVAULT_DECRYPTED_FILE "${PROJECT_SOURCE_DIR}/_temp/KV_dec.bin"
    CACHE FILEPATH "Private independently decrypted keyvault fixture")
add_test(NAME gxbuild3_keyvault_crypto_tests COMMAND gxbuild3_keyvault_crypto_tests
    "${GXBUILD3_KEYVAULT_CPU_KEY_FILE}"
    "${GXBUILD3_KEYVAULT_ENCRYPTED_FILE}"
    "${GXBUILD3_KEYVAULT_DECRYPTED_FILE}"
    --skip-if-missing)
set_tests_properties(gxbuild3_keyvault_crypto_tests PROPERTIES SKIP_RETURN_CODE 77)

add_executable(gxbuild3_cli_fixture_generator CliFixtureGenerator.cpp)
target_link_libraries(gxbuild3_cli_fixture_generator PRIVATE gxbuild3_internal)
gxbuild3_enable_warnings(gxbuild3_cli_fixture_generator)

add_executable(gxbuild3_cli_output_verifier CliOutputVerifier.cpp)
target_link_libraries(gxbuild3_cli_output_verifier PRIVATE gxbuild3_internal)
gxbuild3_enable_warnings(gxbuild3_cli_output_verifier)

add_test(NAME gxbuild3_cli_integration_tests
    COMMAND ${CMAKE_COMMAND}
        -DGXBUILD3_EXE=$<TARGET_FILE:gxbuild3>
        -DGXBUILD3_FIXTURE_GENERATOR=$<TARGET_FILE:gxbuild3_cli_fixture_generator>
        -DGXBUILD3_OUTPUT_VERIFIER=$<TARGET_FILE:gxbuild3_cli_output_verifier>
        -DTEST_ROOT=${CMAKE_BINARY_DIR}/cli-integration-tests
        -P ${CMAKE_CURRENT_SOURCE_DIR}/CliIntegrationTests.cmake)

add_test(NAME gxbuild3_error_convention_guard
    COMMAND ${CMAKE_COMMAND}
        -DSOURCE_ROOT=${PROJECT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/ErrorConventionGuard.cmake)

find_program(GXBUILD3_BASH_EXECUTABLE NAMES bash)
if(UNIX)
    # Byte oracle over build_all.sh against tests/golden/build_all.sha256, plus the
    # parse snapshot of every image it writes against tests/golden/build_all.parse.txt
    # (gxbuild3_flashimage_golden_tests --snapshot). The capture target below is the
    # only way to rewrite either golden; CTest never passes GXBUILD3_UPDATE_GOLDEN.
    set(GXBUILD3_FLASHIMAGE_ARGS
        -DGXBUILD3_EXE=$<TARGET_FILE:gxbuild3>
        -DGXBUILD3_SUPPORT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/gxBuild-support-files
        -DGXBUILD3_BASH=${GXBUILD3_BASH_EXECUTABLE}
        -DGXBUILD3_GOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/golden/build_all.sha256
        -DGXBUILD3_SNAPSHOT_TOOL=$<TARGET_FILE:gxbuild3_flashimage_golden_tests>
        -DGXBUILD3_PARSE_GOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/golden/build_all.parse.txt
        -DGXBUILD3_SCRATCH_DIR=${CMAKE_BINARY_DIR}/flashimage-tests)
    add_test(NAME gxbuild3_flashimage_tests
        COMMAND ${CMAKE_COMMAND} ${GXBUILD3_FLASHIMAGE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/FlashImageTests.cmake)
    set_tests_properties(gxbuild3_flashimage_tests PROPERTIES TIMEOUT 1800 SKIP_RETURN_CODE 77)
    add_custom_target(gxbuild3_flashimage_golden_update
        COMMAND ${CMAKE_COMMAND} ${GXBUILD3_FLASHIMAGE_ARGS} -DGXBUILD3_UPDATE_GOLDEN=1
            -P ${CMAKE_CURRENT_SOURCE_DIR}/FlashImageTests.cmake
        DEPENDS gxbuild3 gxbuild3_flashimage_golden_tests
        USES_TERMINAL
        COMMENT "Capturing tests/golden/build_all.sha256 and build_all.parse.txt (two identical runs required)")
endif()

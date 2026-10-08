# gxbuild3_golden_tests: the golden binary. It owns the text goldens in tests/golden (more join
# as their old binaries are ported) and its main is golden_main (support/golden/Golden.hpp):
# no argument runs the tests, --list-goldens prints the registered goldens and
# --update <name>... re-renders them (twice, written only when both renders agree). CTest only
# compares. The helper suites of 5 or more cheap cases run as one bundled entry each, and so do
# StfsSystemUpdateGolden, whose four cases share the 11.8 MB su20076000 package read once per
# process, and ObjectsCorpusGolden, whose eight cases share one corpus render per process (about
# 0.2 s); the other goldens (WireCorpusGolden's three cases included: its 145 stage fixtures
# load and render in about 0.2 s) and the single-case suites (FlashFsRootGolden's whole-file
# render takes about 2.5 s) are one entry per TEST. So are the three FlashImage goldens: the
# donor (flashimage_golden) and failure table each render in a few seconds, the whole-file
# flashimage_matrix writes 48 full-size images (about 25 s) until it is sectioned. So are the
# three run_build goldens: run_build_failures (60 refused builds, under a second),
# run_build_digests (32 builds, about 12 s) and extract_projections_synthetic (6 builds and 6
# projection passes, about 23 s), the last two whole-file until they are sectioned.
gxbuild3_add_gtest(gxbuild3_golden_tests
    PREFIX golden
    LABELS golden slow
    TIMEOUT 600
    MAIN ${CMAKE_CURRENT_SOURCE_DIR}/support/golden/GoldenMain.cpp
    LIBS gxbuild3_flashimage_render gxbuild3_cli
    SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/support/golden/Golden.cpp
        ${CMAKE_CURRENT_LIST_DIR}/GoldenHelperTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/GoldenMainTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/GoldenSectionTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/GoldenUpdateTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/GoldenSnapshotSelfTestGolden.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashFsRootRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashFsRootGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashImageDonorRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashImageDonorGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashImageMatrixRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashImageMatrixGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashImageFailureRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashImageFailureGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ExtractProjectionSyntheticRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ExtractProjectionSyntheticGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ObjectsCorpusRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ObjectsCorpusGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/RunBuildDigestRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/RunBuildDigestGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/RunBuildFailureRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/RunBuildFailureGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StfsSystemUpdateGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/WireCorpusRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/WireCorpusGoldenTests.cpp
    BUNDLE
        GoldenDifference
        GoldenArgs
        GoldenSection
        GoldenUpdate
        ObjectsCorpusGolden
        StfsSystemUpdateGolden)

# Capture targets, one per golden, by name only and never run by CTest:
# `cmake --build build --target gxbuild3_golden_update_<name>`. GXBUILD3_GOLDEN_DIR in the
# environment redirects the write to a scratch copy.
set(GXBUILD3_TEXT_GOLDENS
    extract_projections_synthetic
    flashfs_roots
    flashimage_failures
    flashimage_golden
    flashimage_matrix
    golden_snapshot_selftest
    objects_corpus
    run_build_digests
    run_build_failures
    stfs_su20076000_entries
    stfs_su20076000_metadata
    wire_corpus_bootloaders)
foreach(golden IN LISTS GXBUILD3_TEXT_GOLDENS)
    add_custom_target(gxbuild3_golden_update_${golden}
        COMMAND gxbuild3_golden_tests --update ${golden}
        DEPENDS gxbuild3_golden_tests
        USES_TERMINAL
        COMMENT "Re-rendering tests/golden/${golden}.txt (written only when two renders agree)")
endforeach()

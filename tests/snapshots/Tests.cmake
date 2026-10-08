# gxbuild3_golden_tests: the golden binary. It owns every text golden in tests/golden except the
# oracle's build_all.parse.txt, each through one GX_GOLDEN registration, and the listing guard
# fails when --list-goldens or GXBUILD3_TEXT_GOLDENS below drifts from that set. Its main is
# golden_main (support/golden/Golden.hpp):
# no argument runs the tests, --list-goldens prints the registered goldens and
# --update <name>... re-renders them (twice, written only when both renders agree). CTest only
# compares. The helper suites of 5 or more cheap cases run as one bundled entry each, and so do
# StfsSystemUpdateGolden, whose four cases share the 11.8 MB su20076000 package read once per
# process, and ObjectsCorpusGolden, whose eight cases share one corpus render per process (about
# 0.2 s); the other goldens (WireCorpusGolden's three cases included: its 145 stage fixtures
# load and render in about 0.2 s) and the single-case suites (FlashFsRootGolden's whole-file
# render takes about 2.5 s) are one entry per TEST. So are two FlashImage goldens: the donor
# (flashimage_golden) and the failure table each render in a few seconds. flashimage_matrix is
# compared per section: FlashImageMatrixCell is instantiated per build type over the three
# shapes, each instantiation one bundle of three cells (six full-size images, about 2-4 s, a Big
# cell most of it), and FlashImageMatrixGolden bundles the header slice, the cell-count trailer
# and the partition check (about 2 s, the three zeroed header images). run_build_digests is
# compared per row: RunBuildDigest is instantiated per build type over the four layouts, each
# instantiation one bundle of four rows (eight builds, about 3 s), and its plain companion
# RunBuildDigestGolden.IsPartitioned is one entry. run_build_failures (60 refused builds, under a
# second) is compared whole, one entry per TEST. extract_projections_synthetic is compared per
# case: each Case/ExtractProjectionSynthetic row builds its image twice and projects it twice
# (several seconds), so each row is its own entry (PER_ROW), and its plain companion
# ExtractProjectionSyntheticGolden.IsPartitioned is one entry. The two goldens over the tracked
# mydata/image.bin are compared per section too: Build/MydataBuild (the three variants, six
# builds, about 2 s) is one bundled entry, each Case/MydataProjection row (two projection passes,
# the Glitch2 row its rebuild too) is its own entry (PER_ROW), and MydataGolden bundles the
# donor's nonce check and the two partition checks. Each of these cases reads the donor and the
# builds it needs through a per-process cache, so none depends on another having run.
# ResolverDigestGolden (resolver_build_requests: two pinned donor builds and ten resolves in the
# test's ScratchDir) is one entry, compared whole.
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
        ${CMAKE_CURRENT_LIST_DIR}/MydataRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/MydataGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ExtractProjectionSyntheticRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ExtractProjectionSyntheticGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ObjectsCorpusRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ObjectsCorpusGoldenTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverDigestRender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverDigestGoldenTests.cpp
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
        StfsSystemUpdateGolden
        FlashImageMatrixGolden
        Retail/FlashImageMatrixCell
        Jtag/FlashImageMatrixCell
        Glitch/FlashImageMatrixCell
        Glitch2/FlashImageMatrixCell
        Glitch2m/FlashImageMatrixCell
        Glitch3/FlashImageMatrixCell
        Devgl/FlashImageMatrixCell
        Devkit/FlashImageMatrixCell
        Retail/RunBuildDigest
        Glitch2/RunBuildDigest
        Devkit/RunBuildDigest
        Devgl/RunBuildDigest
        Build/MydataBuild
        MydataGolden
    PER_ROW
        Case/ExtractProjectionSynthetic
        Case/MydataProjection)

# Capture targets, one per golden, by name only and never run by CTest:
# `cmake --build build --target gxbuild3_golden_update_<name>`. GXBUILD3_GOLDEN_DIR in the
# environment redirects the write to a scratch copy.
set(GXBUILD3_TEXT_GOLDENS
    extract_projections_mydata
    extract_projections_synthetic
    flashfs_roots
    flashimage_failures
    flashimage_golden
    flashimage_matrix
    golden_snapshot_selftest
    objects_corpus
    orchestration_mydata_builds
    resolver_build_requests
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

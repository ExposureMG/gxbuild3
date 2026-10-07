# gxbuild3_golden_tests: the golden binary. It owns the text goldens in tests/golden (more join
# as their old binaries are ported) and its main is golden_main (support/golden/Golden.hpp):
# no argument runs the tests, --list-goldens prints the registered goldens and
# --update <name>... re-renders them (twice, written only when both renders agree). CTest only
# compares. The helper suites of 5 or more cheap cases run as one bundled entry each, and so does
# StfsSystemUpdateGolden, whose four cases share the 11.8 MB su20076000 package read once per
# process; the other goldens and the single-case suites are one entry per TEST.
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
        ${CMAKE_CURRENT_LIST_DIR}/StfsSystemUpdateGoldenTests.cpp
    BUNDLE
        GoldenDifference
        GoldenArgs
        GoldenSection
        GoldenUpdate
        StfsSystemUpdateGolden)

# Capture targets, one per golden, by name only and never run by CTest:
# `cmake --build build --target gxbuild3_golden_update_<name>`. GXBUILD3_GOLDEN_DIR in the
# environment redirects the write to a scratch copy.
set(GXBUILD3_TEXT_GOLDENS
    golden_snapshot_selftest
    stfs_su20076000_entries
    stfs_su20076000_metadata)
foreach(golden IN LISTS GXBUILD3_TEXT_GOLDENS)
    add_custom_target(gxbuild3_golden_update_${golden}
        COMMAND gxbuild3_golden_tests --update ${golden}
        DEPENDS gxbuild3_golden_tests
        USES_TERMINAL
        COMMENT "Re-rendering tests/golden/${golden}.txt (written only when two renders agree)")
endforeach()

# gxbuild3_objects_tests: src/nand/objects and src/patchers (more object suites join as their old
# tests are ported). Row/PatchsetMalformed, Pattern/SignaturePattern,
# Row/SignaturePatternBadToken and Vector/KeyvaultVersionVector are cheap tables, one bundled entry
# each; LooseKeyvault (9 cases on one keyvault, milliseconds) is one bundled entry; Patchset (4
# cases), SignaturePatternEdge (2), SignaturePatch (2), PatchSection (1) and KeyvaultCpuKey (1) are
# suites of fewer than five cases, one entry per case.
gxbuild3_add_gtest(gxbuild3_objects_tests
    PREFIX objects
    LABELS unit objects
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/KeyvaultVersionTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/PatcherTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/PatchsetTests.cpp
    BUNDLE
        Row/PatchsetMalformed
        Pattern/SignaturePattern
        Row/SignaturePatternBadToken
        LooseKeyvault
        Vector/KeyvaultVersionVector)

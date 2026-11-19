# gxbuild3_objects_tests: src/nand/objects and src/patchers (more object suites join as their old
# tests are ported). Row/PatchsetMalformed, Pattern/SignaturePattern,
# Row/SignaturePatternBadToken, Vector/KeyvaultVersionVector, Features/FcrtRequirement,
# Type/PatchsetFileKind (6 wrong-kind files) and Base/XConfig (2 region bases) are cheap tables,
# one bundled entry each; LooseKeyvault (9 cases on one keyvault, milliseconds) is one bundled
# entry; Patchset (4 cases), PatchsetDelimiterGate (2), SignaturePatternEdge (2), SignaturePatch
# (2), PatchSection (1),
# KeyvaultCpuKey (1), SecuredFileStamp (1), CrlSeal (2), DaeSeal (2), ExtendedSeal (2),
# SecdataSeal (2), LooseSecuredFiles (1), SecuredFileDraws (1), FcrtSeal (4) and
# FcrtRequirementShort (1) are suites of fewer than five cases, one entry per case.
gxbuild3_add_gtest(gxbuild3_objects_tests
    PREFIX objects
    LABELS unit objects
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/FcrtTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/KeyvaultVersionTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/PatcherTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/PatchsetTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SecuredFileSealTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/XConfigTests.cpp
    BUNDLE
        Row/PatchsetMalformed
        Pattern/SignaturePattern
        Row/SignaturePatternBadToken
        LooseKeyvault
        Vector/KeyvaultVersionVector
        Features/FcrtRequirement
        Type/PatchsetFileKind
        Base/XConfig)

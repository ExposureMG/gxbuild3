# gxbuild3_bootloader_tests: src/nand/bootloaders. BootloaderLayout is the compile-time
# sizeof/offsetof pins of every record in Common.hpp plus one run-time case that counts them;
# KeyChain (the CB/CD key chain, 4 cases) is a suite of fewer than five cases. Stage (2 cases),
# StageCryptRecord (4), StageNonce (2), StageCryptFailure (3), CryptSingleBl (1), CfCalcMac (1),
# XerunnerSeal (2), SmcDetection (1) and UnboundCbB (1) are suites of fewer than five cases too,
# one entry per case. Row/StageDeclaredSize (9 parses), Flags/CbBRegime (4 regimes x 2 CPU keys)
# and Flags/CbBBinding (3 regimes) are cheap tables, one bundled entry each.
# glitch/ seals synthetic chains through run_build (about 0.3 s per build in Release):
# ChainPolicy is instantiated per family (Retail 2, Glitch 3, Glitch2m 3 and Glitch3 2 rows)
# and RetailDigest per regime (Single, Split0800, Split1800, 5 changes each), one bundled entry
# per group; the 2- and 3-row tables (Vector/RetailDigestVector, Row/CbBPerboxLdv,
# Type/SingleCbPairing, Type/PatchedStageSealing, Case/Glitch3IncompleteChain and
# Row/Glitch3SealsCbX) are one bundled entry each; JtagChain, Glitch3Replacement, CbXFix and
# CfCgNonce are single cases.
gxbuild3_add_gtest(gxbuild3_bootloader_tests
    PREFIX bootloaders
    LABELS unit bootloaders slow
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/BootloaderLayoutPins.cpp
        ${CMAKE_CURRENT_LIST_DIR}/CryptoReferenceTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/KeyChainTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StageRefusalTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StageTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/glitch/CbBPerboxLdvTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/glitch/CfCgNonceTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/glitch/ChainPolicyTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/glitch/Glitch3Tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/glitch/GlitchFixture.cpp
        ${CMAKE_CURRENT_LIST_DIR}/glitch/RetailDigestTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/glitch/SingleCbAndJtagTests.cpp
    BUNDLE
        Row/StageDeclaredSize
        Flags/CbBRegime
        Flags/CbBBinding
        Retail/ChainPolicy
        Glitch/ChainPolicy
        Glitch2m/ChainPolicy
        Glitch3/ChainPolicy
        Single/RetailDigest
        Split0800/RetailDigest
        Split1800/RetailDigest
        Vector/RetailDigestVector
        Row/CbBPerboxLdv
        Type/SingleCbPairing
        Type/PatchedStageSealing
        Case/Glitch3IncompleteChain
        Row/Glitch3SealsCbX)

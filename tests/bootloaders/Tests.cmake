# gxbuild3_bootloader_tests: src/nand/bootloaders (more bootloader suites join as their old tests
# are ported). BootloaderLayout is the compile-time sizeof/offsetof pins of every record in
# Common.hpp plus one run-time case that counts them; KeyChain (the CB/CD key chain, 4 cases) is
# a suite of fewer than five cases. Stage (2 cases), StageCryptRecord (4), StageNonce (2),
# StageCryptFailure (3), CryptSingleBl (1), CfCalcMac (1), XerunnerSeal (2), SmcDetection (1) and
# UnboundCbB (1) are suites of fewer than five cases too, one entry per case. Row/StageDeclaredSize
# (9 parses), Flags/CbBRegime (4 regimes x 2 CPU keys) and Flags/CbBBinding (3 regimes) are cheap
# tables, one bundled entry each.
gxbuild3_add_gtest(gxbuild3_bootloader_tests
    PREFIX bootloaders
    LABELS unit bootloaders slow
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/BootloaderLayoutPins.cpp
        ${CMAKE_CURRENT_LIST_DIR}/CryptoReferenceTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/KeyChainTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StageRefusalTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StageTests.cpp
    BUNDLE
        Row/StageDeclaredSize
        Flags/CbBRegime
        Flags/CbBBinding)

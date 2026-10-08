# gxbuild3_nand_tests: src/nand (the driver, FlashImage's settings, anchor, mobile and FlashFS
# placement, FlashFS allocation, the big- and small-block FlashFS, its transactional load and its
# corrupt-input reads, the runtime anchors, the CG spill chain, the JTAG window, the payload
# layout's overflow steps and the embedded freeBOOT payloads; more nand suites join as their old
# tests are ported).
# DriverSpare (5 driver cases, no image written) is a cheap suite of five cases, one bundled
# entry. Shape/BadBlockMark (Small, Big), Shape/SmcConfig (two cases over the Small, Big and
# eMMC settings-block shapes), Shape/SettingsBlock (the same three shapes), Shape/MobileData (the
# latest copy on Small and NewSmall) and Shape/MobileDataLayout (Small, NewSmall, Big) are cheap
# tables, one bundled entry each. Their plain companions SmcConfigChecksum (1), SmcSize (1),
# MobileDataBigBlock (1) and MobileDataWrite (2), and CoronaAnchor (3), FlashImageFsPlacement
# (4) and FlashFsAllocation (2) are suites of fewer than five cases, one entry per case.
# Mode/FlashFsSmallBlock (Small, NewSmall) is a cheap table, one bundled entry; its plain
# companion FlashFsSmallBlockLayout (3), FlashFsRootCodec (1), FlashFsLoad (1), FlashFsEmmc (1)
# and FlashFsCorruptInput (2) are one entry per case. Pin/FlashFsLoadPin (the nine [load <pin>]
# lines of flashfs_roots.txt, one row each) is a cheap table, one bundled entry. FlashFsBigBlock
# has eight cases, but its big-block serializes take about 0.7 s together, past the ~1 s budget
# of a bundled suite with the rest: one entry per case.
# AnchorLayout (Glitch2 and Glitch2m rows, each writing and re-reading a full image) is
# instantiated per shape, Small/, Big/ and Emmc/AnchorLayout, one bundled entry per shape; its
# plain companion AnchorLayoutRoundTrip (1), XeLL (1), PayloadRange (1) and FreebootProvider (1)
# are one entry per case. Mode/JtagWindow (Small, Big) is a table, one bundled entry.
# Type/SpillChain (Retail, Glitch2, Jtag) rewrites a big-block image several times per row: each
# row is its own entry (PER_ROW).
gxbuild3_add_gtest(gxbuild3_nand_tests
    PREFIX nand
    LABELS unit nand slow
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/AnchorFixture.cpp
        ${CMAKE_CURRENT_LIST_DIR}/AnchorLayoutTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/CoronaAnchorTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/DriverSpareTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashFsAllocationTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashFsBigBlockTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashFsCorruptInputTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashFsLoadTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashFsSmallBlockTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashImageFsPlacementTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FreebootProviderTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/JtagWindowTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/MobileDataTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/PayloadRangeTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SettingsBlockTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SpillChainTests.cpp
    BUNDLE
        DriverSpare
        Shape/BadBlockMark
        Shape/SmcConfig
        Shape/SettingsBlock
        Shape/MobileData
        Shape/MobileDataLayout
        Mode/FlashFsSmallBlock
        Pin/FlashFsLoadPin
        Small/AnchorLayout
        Big/AnchorLayout
        Emmc/AnchorLayout
        Mode/JtagWindow
    PER_ROW
        Type/SpillChain)

# gxbuild3_orchestration_tests: run_build and the extract_* cores (src/BuildRunner.cpp), ported
# group by group from tests/BuildRunnerTests.cpp (more suites join as its groups are ported).
# RunBuildPatching (8 cases: glitch CB/CB_B/CD patching, the clean retail SMC reboot patch,
# noblpatch, nopatch, overflow and the retail/devkit add-on refusal), RunBuildJtag (4 cases: the
# JTAG patch region, window items, window padding and the clean-SMC refusal), PatchSlotLayout
# (16 cases: KHV anchors, XeLL slot shifts, fixed-payload collisions and extraction ownership;
# the layout loops stay one case each under SCOPED_TRACE), RunBuildInput (5 cases: the input and
# donor contract and the fixed payload sizes), RunBuildMobile (12 cases: eMMC anchor mobiles,
# donor overlays, bad blocks, the SMC tail and the fixed payloads) and RunBuildSettings (1 case),
# ExtractAll (3), ExtractInfo (4) and ExtractionFailure (2), FreshLayout (2 cases: the driver mode
# of each image type and a two-slot replacement over a one-slot donor), NandHeader (3 cases: 0x74,
# the pairing and copyright notice, the hacked boot flags and the KHV tail), FlashFsOverlay (10
# cases: big-block round trips, donor roots of higher sequence, allocation limits, the directory
# capacity and the xeBuild layout under a pinned build time) and SecuredFlashFs (4 cases: secured
# files round-trip, are sealed for the console, a damaged fcrt.bin and unusable extended/secdata
# made up clean), BootChainMetadata (8 cases: extraction round trips of the chain and the fixed
# payloads, the CB/CB_B/CF LDV and pairing overrides, the extended CF header, the unbound first
# JTAG pair and the unwritable CB/CF per-box refusals), ZeroCpuKey (2 cases: a zero-paired CB_B
# chain and the donor keyvault left sealed) and BootChainRecords (10 cases: the donor chain
# replaced by input presence, the actual CF slot base, stage header endianness, the CB console
# allowance and the header-only/orphan record refusals). Orchestration stays one ctest entry per
# case (SUITE RULE): most cases run run_build, 0.1-2 s in Release, and the few stage-record cases
# of BootChainRecords that do not stay beside them. The one bundle is Size/KeyvaultSummaryOsig (3
# rows of summarize_keyvault on a hand-made keyvault, microseconds). RunBuildImage.cpp holds the
# shared image reads.
gxbuild3_add_gtest(gxbuild3_orchestration_tests
    PREFIX orchestration
    LABELS unit orchestration slow
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/BootChainMetadataTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/BootChainRecordsTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ExtractionTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FlashFsOverlayTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FreshLayoutHeaderTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/InputAndDonorTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/MobileAndSettingsTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/PatchSlotLayoutTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/PatchingTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/RunBuildImage.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SecuredFlashFsTests.cpp
    BUNDLE
        Size/KeyvaultSummaryOsig)

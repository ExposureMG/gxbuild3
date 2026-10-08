# gxbuild3_orchestration_tests: run_build and the extract_* cores (src/BuildRunner.cpp), ported
# group by group from tests/BuildRunnerTests.cpp (more suites join as its groups are ported).
# RunBuildPatching (8 cases: glitch CB/CB_B/CD patching, the clean retail SMC reboot patch,
# noblpatch, nopatch, overflow and the retail/devkit add-on refusal), RunBuildJtag (4 cases: the
# JTAG patch region, window items, window padding and the clean-SMC refusal) and PatchSlotLayout
# (16 cases: KHV anchors, XeLL slot shifts, fixed-payload collisions and extraction ownership;
# the layout loops stay one case each under SCOPED_TRACE). Every case runs run_build, 0.1-2 s in
# Release: one ctest entry per case, no bundles. RunBuildImage.cpp holds the shared image reads.
gxbuild3_add_gtest(gxbuild3_orchestration_tests
    PREFIX orchestration
    LABELS unit orchestration slow
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/PatchSlotLayoutTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/PatchingTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/RunBuildImage.cpp)

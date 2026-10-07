# gxbuild3_utils_tests: src/utils (more utils suites join as their old tests are ported).
# BuildTime: the two cheap tables Row/FatTimestamp and Row/SourceDateEpoch run as one bundled
# ctest entry each; FlashFsBuildTimestamp and the four FatTimestampZone cases, which change the
# process's TZ (and whose British-summer-time case skips on WIN32), are one entry per case.
gxbuild3_add_gtest(gxbuild3_utils_tests
    PREFIX utils
    LABELS unit utils
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/BuildTimeTests.cpp
    BUNDLE
        Row/FatTimestamp
        Row/SourceDateEpoch)

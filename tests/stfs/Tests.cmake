# gxbuild3_stfs_tests: src/stfs over the area-local synthetic PIRS packages (PirsPackage.hpp)
# and the tracked 17559/su20076000_00000000. StfsPath, StfsChain and StfsFileTable are cheap
# suites of 5 or more cases and Row/StfsErrorCode (32 rows) a cheap table, one bundled ctest
# entry each. NeedsDevFull/StfsErrorCode, the one row that skips without /dev/full, is its own
# instantiation outside the bundle, discovered per row. StfsSafeJoin (WIN32-only, skips
# elsewhere) and StfsExtractToDisk (skips without /dev/full) are suites of their own; StfsHeader,
# StfsVerify, StfsMetadata and StfsSystemUpdate (fewer than five cases) are one entry per case.
gxbuild3_add_gtest(gxbuild3_stfs_tests
    PREFIX stfs
    LABELS unit stfs
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/PirsPackage.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StfsChainTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StfsErrorTableTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StfsFileTableTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StfsHeaderTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StfsMetadataTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StfsPathTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StfsSystemUpdateTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StfsVerifyTests.cpp
    BUNDLE
        StfsPath
        StfsChain
        StfsFileTable
        Row/StfsErrorCode
    PER_ROW
        NeedsDevFull/StfsErrorCode)

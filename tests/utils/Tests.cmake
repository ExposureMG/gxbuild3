# gxbuild3_utils_tests: src/utils (more utils suites join as their old tests are ported).
# BuildTime: the two cheap tables Row/FatTimestamp and Row/SourceDateEpoch run as one bundled
# ctest entry each; FlashFsBuildTimestamp and the four FatTimestampZone cases, which change the
# process's TZ (and whose British-summer-time case skips on WIN32), are one entry per case.
# XeRsa: the three XeRsaSd cases share the generated RSA-2048 test key (about 0.5 s per process),
# so they run as one bundled entry that makes it once; BigUint, Crc32 and Fuseset are suites of
# fewer than five cases, one entry per case.
# FileManager (FileManagerTest.hpp, one fixture subclass per file): FileManagerLookup,
# FileManagerBootloader, FileManagerIni, FileManagerScan and FileManagerStfsCache are cheap suites
# of 5 or more cases and Row/FileManagerUnconfinedPath a cheap table, one bundled entry each;
# FileManagerSymlink, which skips where directory symlinks cannot be made, and UtilsIo (1) are one
# entry per case.
gxbuild3_add_gtest(gxbuild3_utils_tests
    PREFIX utils
    LABELS unit utils
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/BuildTimeTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FileManagerBootloaderTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FileManagerIniTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FileManagerLookupTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FileManagerScanTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FileManagerStfsCacheTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FileManagerTest.cpp
        ${CMAKE_CURRENT_LIST_DIR}/FusesetTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/UtilsIoTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/XeRsaTests.cpp
    BUNDLE
        Row/FatTimestamp
        Row/SourceDateEpoch
        XeRsaSd
        FileManagerLookup
        FileManagerBootloader
        FileManagerIni
        FileManagerScan
        FileManagerStfsCache
        Row/FileManagerUnconfinedPath)

# gxbuild3_core_tests: the test support library's self-tests, the CPU keys, src/Error.hpp and
# src/Wire.hpp (more core suites join as their old tests are ported). SupportExpect,
# SupportBytes, ErrorResult and WireRecord are cheap suites of 5 or more cases, so each runs as
# one bundled ctest entry; WireLayoutPins (the compile-time pins plus one run-time case),
# WireCursor, WireFormat and WireLog (the Log capture fixture) are one entry per case.
gxbuild3_add_gtest(gxbuild3_core_tests
    PREFIX core
    LABELS unit core
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/ErrorTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/KeysTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SupportExpectTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SupportSelfTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/WireCursorTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/WireFormatTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/WireLayoutPins.cpp
        ${CMAKE_CURRENT_LIST_DIR}/WireRecordTests.cpp
    BUNDLE
        SupportExpect
        SupportBytes
        ErrorResult
        WireRecord)

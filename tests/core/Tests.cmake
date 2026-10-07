# gxbuild3_core_tests: the test support library's self-tests, the CPU keys and src/Error.hpp
# (more core suites join as their old tests are ported). SupportExpect, SupportBytes and
# ErrorResult are cheap suites of 5 or more cases, so each runs as one bundled ctest entry.
gxbuild3_add_gtest(gxbuild3_core_tests
    PREFIX core
    LABELS unit core
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/ErrorTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/KeysTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SupportExpectTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SupportSelfTests.cpp
    BUNDLE
        SupportExpect
        SupportBytes
        ErrorResult)

# gxbuild3_cli_tests: src/cli (the resolver suites join as BuildInputResolverTests.cpp is
# ported). CommandLine (5 cheap cases), Block/CommandLineBlockType (4 block types) and
# Argv/CommandLineError (26 refused command lines) run as one bundled ctest entry each.
# BuildCommand (3 cases) and BuildCommandTest (2 cases in a scratch directory) are suites of
# fewer than five cases, one entry per case.
gxbuild3_add_gtest(gxbuild3_cli_tests
    PREFIX cli
    LABELS unit cli
    LIBS gxbuild3_cli
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/BuildCommandTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/CommandLineErrorTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/CommandLineTests.cpp
    BUNDLE
        CommandLine
        Block/CommandLineBlockType
        Argv/CommandLineError)

# gxbuild3_cli_tests: src/cli (the resolver suites ported from BuildInputResolverTests.cpp,
# whose resolver_build_requests golden is the golden binary's). CommandLine (5 cheap cases), Block/CommandLineBlockType (4 block types) and
# Argv/CommandLineError (26 refused command lines) run as one bundled ctest entry each.
# BuildCommand (3 cases) and BuildCommandTest (2 cases in a scratch directory) are suites of
# fewer than five cases, one entry per case.
# Resolver (ResolverTest.hpp, a ResolverTree in each test's scratch directory, one fixture
# subclass per file): the ResolverRoots, ResolverOptions and ResolverCpuKey cases are one entry
# per case; the 35-row options.ini decode table runs as two bundled entries,
# ThroughFile/OptionsText and ThroughParseOptionsText/OptionsText. ResolverDonor,
# ResolverLooseDonor and ResolverMetadata (donor run_builds, the BigBlock flake history) are one
# entry per case; the three refused -c metadata rows run as one bundled entry,
# Row/CliMetadataProvenance. ResolverPayload and ResolverPatchset (resolves, some with donor
# run_builds) are one entry per case; the automatic patch file names of the five hacked build
# types and the two types that select none run as two bundled entries, Row/AutomaticPatchsetName
# and Row/NoAutomaticPatchset.
gxbuild3_add_gtest(gxbuild3_cli_tests
    PREFIX cli
    LABELS unit cli
    LIBS gxbuild3_cli
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/BuildCommandTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/CommandLineErrorTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/CommandLineTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverCpuKeyTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverDonorTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverLooseDonorTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverMetadataTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverOptionsTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverPatchsetTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverPayloadTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverRootsTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResolverTest.cpp
    BUNDLE
        CommandLine
        Block/CommandLineBlockType
        Argv/CommandLineError
        ThroughFile/OptionsText
        ThroughParseOptionsText/OptionsText
        Row/CliMetadataProvenance
        Row/AutomaticPatchsetName
        Row/NoAutomaticPatchset)

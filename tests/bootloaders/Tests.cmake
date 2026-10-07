# gxbuild3_bootloader_tests: src/nand/bootloaders (more bootloader suites join as their old tests
# are ported). BootloaderLayout is the compile-time sizeof/offsetof pins of every record in
# Common.hpp plus one run-time case that counts them; KeyChain (the CB/CD key chain, 4 cases) is
# a suite of fewer than five cases. Both are one entry per case.
gxbuild3_add_gtest(gxbuild3_bootloader_tests
    PREFIX bootloaders
    LABELS unit bootloaders slow
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/BootloaderLayoutPins.cpp
        ${CMAKE_CURRENT_LIST_DIR}/KeyChainTests.cpp)

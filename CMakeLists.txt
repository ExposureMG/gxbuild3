cmake_minimum_required(VERSION 3.25)
include(cmake/SelectCompilers.cmake)
project(GxBuild3 LANGUAGES C CXX)
gxbuild3_validate_compilers()

include(CTest)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Clang 22+ has an -O3 optimizer hang with C++23 (e.g., FlashFileSystem.cpp).
# Force -O2 for Clang Release builds as a workaround.
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG" CACHE STRING "" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(extern/argparse)
add_subdirectory(extern/GxCrypt)
add_subdirectory(extern/spdlog)
add_subdirectory(extern/stfs)


set(GXBUILD3_LIB_SOURCES
    src/Args.cpp
    src/BuildRunner.cpp
    src/Library.cpp
    src/ini/IniParser.cpp
    src/nand/FlashDriver.cpp
    src/nand/FlashImage.cpp
    src/nand/bootloaders/2bl.cpp
    src/nand/bootloaders/3bl.cpp
    src/nand/bootloaders/4bl.cpp
    src/nand/bootloaders/5bl.cpp
    src/nand/bootloaders/6bl.cpp
    src/nand/bootloaders/7bl.cpp
    src/nand/bootloaders/BootloaderPacker.cpp
    src/nand/objects/CoronaConfig.cpp
    src/nand/objects/FlashFileSystem.cpp
    src/nand/objects/Keyvault.cpp
    src/nand/objects/MobileData.cpp
    src/nand/objects/Patchset.cpp
    src/nand/objects/SMC.cpp
    src/nand/objects/XConfig.cpp
    src/nand/objects/Xboxupd.cpp
    src/nand/objects/XeLL.cpp
    src/patchers/Patcher.cpp
    src/patchers/Signature.cpp
    src/stfs/StfsContainer.cpp
    src/utils/FileManager.cpp
    src/utils/FusesetGenerator.cpp
    src/utils/Log.cpp
    src/utils/Options.cpp
    src/utils/Utils.cpp
)

add_library(gxbuild3_lib STATIC ${GXBUILD3_LIB_SOURCES})

target_compile_features(gxbuild3_lib PRIVATE cxx_std_23)
set_target_properties(gxbuild3_lib PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_include_directories(gxbuild3_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(gxbuild3_lib PUBLIC
    GxCrypt
    spdlog::spdlog
    stfs
)

add_executable(gxbuild3 src/Main.cpp)

target_compile_features(gxbuild3 PRIVATE cxx_std_23)
set_target_properties(gxbuild3 PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(gxbuild3 PRIVATE
    gxbuild3_lib
    argparse::argparse
    stfs
    GxCrypt
    spdlog::spdlog
)

if(BUILD_TESTING)
    add_test(NAME gxbuild3_compiler_selection_tests
        COMMAND ${CMAKE_COMMAND}
            -DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/compiler-selection-tests
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/CompilerSelectionTests.cmake)

    add_executable(gxbuild3_flashdriver_tests tests/FlashDriverTests.cpp)

    target_compile_features(gxbuild3_flashdriver_tests PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_flashdriver_tests PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )

    target_link_libraries(gxbuild3_flashdriver_tests PRIVATE gxbuild3_lib)
    add_test(NAME gxbuild3_flashdriver_tests COMMAND gxbuild3_flashdriver_tests)
endif()

target_compile_options(gxbuild3_lib PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_options(gxbuild3 PRIVATE -Wall -Wextra -Wpedantic -Werror)
if(BUILD_TESTING)
    target_compile_options(gxbuild3_flashdriver_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

include(GNUInstallDirs)

install(TARGETS gxbuild3 gxbuild3_lib
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

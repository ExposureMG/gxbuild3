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

add_subdirectory(extern/GxCrypt)
add_subdirectory(extern/spdlog)
add_subdirectory(extern/stfs)


set(GXBUILD3_LIB_SOURCES
    src/Args.cpp
    src/BuildRunner.cpp
    src/cli/BuildCommand.cpp
    src/cli/BuildInputResolver.cpp
    src/cli/CommandLine.cpp
    src/InputValidator.cpp
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
    OUTPUT_NAME gxbuild
)

target_link_libraries(gxbuild3 PRIVATE
    gxbuild3_lib
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

    add_executable(gxbuild3_filemanager_tests tests/FileManagerTests.cpp)
    target_compile_features(gxbuild3_filemanager_tests PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_filemanager_tests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(gxbuild3_filemanager_tests PRIVATE gxbuild3_lib)
    target_compile_options(gxbuild3_filemanager_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME gxbuild3_filemanager_tests COMMAND gxbuild3_filemanager_tests)

    add_executable(gxbuild3_input_tests tests/InputTests.cpp)
    target_compile_features(gxbuild3_input_tests PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_input_tests PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_link_libraries(gxbuild3_input_tests PRIVATE gxbuild3_lib)
    target_compile_options(gxbuild3_input_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME gxbuild3_input_tests COMMAND gxbuild3_input_tests)

    add_executable(gxbuild3_commandline_tests tests/CommandLineTests.cpp)
    target_compile_features(gxbuild3_commandline_tests PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_commandline_tests PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_include_directories(gxbuild3_commandline_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(gxbuild3_commandline_tests PRIVATE gxbuild3_lib)
    target_compile_options(gxbuild3_commandline_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME gxbuild3_commandline_tests COMMAND gxbuild3_commandline_tests)

    add_executable(gxbuild3_buildrunner_tests tests/BuildRunnerTests.cpp)
    target_compile_features(gxbuild3_buildrunner_tests PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_buildrunner_tests PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_link_libraries(gxbuild3_buildrunner_tests PRIVATE gxbuild3_lib)
    target_compile_options(gxbuild3_buildrunner_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME gxbuild3_buildrunner_tests COMMAND gxbuild3_buildrunner_tests)

    add_executable(gxbuild3_patchset_tests tests/PatchsetTests.cpp)
    target_compile_features(gxbuild3_patchset_tests PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_patchset_tests PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_link_libraries(gxbuild3_patchset_tests PRIVATE gxbuild3_lib)
    target_compile_options(gxbuild3_patchset_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME gxbuild3_patchset_tests COMMAND gxbuild3_patchset_tests)

    add_executable(gxbuild3_resolver_tests tests/BuildInputResolverTests.cpp)
    target_compile_features(gxbuild3_resolver_tests PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_resolver_tests PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_link_libraries(gxbuild3_resolver_tests PRIVATE gxbuild3_lib)
    target_compile_options(gxbuild3_resolver_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME gxbuild3_resolver_tests COMMAND gxbuild3_resolver_tests)

    add_executable(gxbuild3_buildcommand_tests tests/BuildCommandTests.cpp)
    target_compile_features(gxbuild3_buildcommand_tests PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_buildcommand_tests PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_link_libraries(gxbuild3_buildcommand_tests PRIVATE gxbuild3_lib)
    target_compile_options(gxbuild3_buildcommand_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME gxbuild3_buildcommand_tests COMMAND gxbuild3_buildcommand_tests)

    add_executable(gxbuild3_cli_fixture_generator tests/CliFixtureGenerator.cpp)
    target_compile_features(gxbuild3_cli_fixture_generator PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_cli_fixture_generator PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_link_libraries(gxbuild3_cli_fixture_generator PRIVATE gxbuild3_lib)
    target_compile_options(gxbuild3_cli_fixture_generator PRIVATE -Wall -Wextra -Wpedantic -Werror)

    add_executable(gxbuild3_cli_output_verifier tests/CliOutputVerifier.cpp)
    target_compile_features(gxbuild3_cli_output_verifier PRIVATE cxx_std_23)
    set_target_properties(gxbuild3_cli_output_verifier PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_link_libraries(gxbuild3_cli_output_verifier PRIVATE gxbuild3_lib)
    target_compile_options(gxbuild3_cli_output_verifier PRIVATE -Wall -Wextra -Wpedantic -Werror)

    add_test(NAME gxbuild3_cli_integration_tests
        COMMAND ${CMAKE_COMMAND}
            -DGXBUILD3_EXE=$<TARGET_FILE:gxbuild3>
            -DGXBUILD3_FIXTURE_GENERATOR=$<TARGET_FILE:gxbuild3_cli_fixture_generator>
            -DGXBUILD3_OUTPUT_VERIFIER=$<TARGET_FILE:gxbuild3_cli_output_verifier>
            -DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/cli-integration-tests
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/CliIntegrationTests.cmake)
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

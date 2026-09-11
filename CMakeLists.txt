cmake_minimum_required(VERSION 3.25)
project(GxBuild3 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Clang 22+ has an -O3 optimizer hang with C++23 (e.g., FlashFileSystem.cpp).
# Force -O2 for Clang Release builds as a workaround.
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG" CACHE STRING "" FORCE)
endif()

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
target_include_directories(gxbuild3_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gxbuild3_lib PUBLIC
    GxCrypt
    spdlog::spdlog
    stfs
)

add_executable(gxbuild3 src/Main.cpp)
set_target_properties(gxbuild3 PROPERTIES OUTPUT_NAME gxbuild)
target_link_libraries(gxbuild3 PRIVATE gxbuild3_lib)

include(CTest)
if(BUILD_TESTING)
    function(add_gxbuild3_test name source)
        add_executable(${name} ${source})
        target_link_libraries(${name} PRIVATE gxbuild3_lib)
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    add_gxbuild3_test(gxbuild3_flashdriver_tests tests/FlashDriverTests.cpp)
    add_gxbuild3_test(gxbuild3_flashfs_tests tests/FlashFileSystemTests.cpp)
    add_gxbuild3_test(gxbuild3_filemanager_tests tests/FileManagerTests.cpp)
    add_gxbuild3_test(gxbuild3_input_tests tests/InputTests.cpp)
    add_gxbuild3_test(gxbuild3_commandline_tests tests/CommandLineTests.cpp)
    add_gxbuild3_test(gxbuild3_buildrunner_tests tests/BuildRunnerTests.cpp)
    add_gxbuild3_test(gxbuild3_patchset_tests tests/PatchsetTests.cpp)
    add_gxbuild3_test(gxbuild3_glitch_crypto_tests tests/GlitchCryptoTests.cpp)
    add_gxbuild3_test(gxbuild3_resolver_tests tests/BuildInputResolverTests.cpp)
    add_gxbuild3_test(gxbuild3_buildcommand_tests tests/BuildCommandTests.cpp)
    add_gxbuild3_test(gxbuild3_keyvault_version_tests tests/KeyvaultVersionTests.cpp)

    add_executable(gxbuild3_keyvault_crypto_tests tests/KeyvaultCryptoTests.cpp)
    target_link_libraries(gxbuild3_keyvault_crypto_tests PRIVATE gxbuild3_lib)
    set(GXBUILD3_KEYVAULT_CPU_KEY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/_temp/cpukey.txt"
        CACHE FILEPATH "Private CPU key fixture (32 hex characters)")
    set(GXBUILD3_KEYVAULT_ENCRYPTED_FILE "${CMAKE_CURRENT_SOURCE_DIR}/_temp/KV_en.bin"
        CACHE FILEPATH "Private encrypted keyvault fixture")
    set(GXBUILD3_KEYVAULT_DECRYPTED_FILE "${CMAKE_CURRENT_SOURCE_DIR}/_temp/KV_dec.bin"
        CACHE FILEPATH "Private independently decrypted keyvault fixture")
    add_test(NAME gxbuild3_keyvault_crypto_tests COMMAND gxbuild3_keyvault_crypto_tests
        "${GXBUILD3_KEYVAULT_CPU_KEY_FILE}"
        "${GXBUILD3_KEYVAULT_ENCRYPTED_FILE}"
        "${GXBUILD3_KEYVAULT_DECRYPTED_FILE}"
        --skip-if-missing)
    set_tests_properties(gxbuild3_keyvault_crypto_tests PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(gxbuild3_cli_fixture_generator tests/CliFixtureGenerator.cpp)
    target_link_libraries(gxbuild3_cli_fixture_generator PRIVATE gxbuild3_lib)

    add_executable(gxbuild3_cli_output_verifier tests/CliOutputVerifier.cpp)
    target_link_libraries(gxbuild3_cli_output_verifier PRIVATE gxbuild3_lib)

    add_test(NAME gxbuild3_cli_integration_tests
        COMMAND ${CMAKE_COMMAND}
            -DGXBUILD3_EXE=$<TARGET_FILE:gxbuild3>
            -DGXBUILD3_FIXTURE_GENERATOR=$<TARGET_FILE:gxbuild3_cli_fixture_generator>
            -DGXBUILD3_OUTPUT_VERIFIER=$<TARGET_FILE:gxbuild3_cli_output_verifier>
            -DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/cli-integration-tests
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/CliIntegrationTests.cmake)
endif()

include(GNUInstallDirs)
install(TARGETS gxbuild3 gxbuild3_lib
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

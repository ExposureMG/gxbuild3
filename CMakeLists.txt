cmake_minimum_required(VERSION 3.29)
project(GxBuild3 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_subdirectory(extern/GxCrypt)
add_subdirectory(extern/spdlog)

# Clang -O3 hangs on C++23 code such as FlashFileSystem.cpp. Cap Release at -O2 for
# gxbuild3 targets only (directory scope, after extern/); the later -O2 overrides -O3.
add_compile_options("$<$<AND:$<CXX_COMPILER_ID:Clang>,$<CONFIG:Release>>:-O2>")

# Warnings are errors on gxbuild3's own targets only; extern/ targets keep their own flags.
function(gxbuild3_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

set(GXBUILD3_LIB_SOURCES
    src/Args.cpp
    src/BuildRunner.cpp
    src/InputValidator.cpp
    src/Library.cpp
    src/ini/IniParser.cpp
    src/nand/FlashDriver.cpp
    src/nand/FlashImageCrypt.cpp
    src/nand/FlashImageLayout.cpp
    src/nand/FlashImageParse.cpp
    src/nand/FlashImageWrite.cpp
    src/nand/bootloaders/2bl.cpp
    src/nand/bootloaders/3bl.cpp
    src/nand/bootloaders/4bl.cpp
    src/nand/bootloaders/5bl.cpp
    src/nand/bootloaders/6bl.cpp
    src/nand/bootloaders/7bl.cpp
    src/nand/bootloaders/BootloaderPacker.cpp
    src/nand/objects/CoronaConfig.cpp
    src/nand/objects/FlashFileSystem.cpp
    src/nand/objects/Freeboot.cpp
    src/nand/objects/Keyvault.cpp
    src/nand/objects/MobileData.cpp
    src/nand/objects/Patchset.cpp
    src/nand/objects/SecuredFiles.cpp
    src/nand/objects/SMC.cpp
    src/nand/objects/XConfig.cpp
    src/nand/objects/Xboxupd.cpp
    src/nand/objects/XeLL.cpp
    src/patchers/Patcher.cpp
    src/patchers/Signature.cpp
    src/stfs/BlockParser.cpp
    src/stfs/FileExtractor.cpp
    src/stfs/FileTableParser.cpp
    src/stfs/HashVerifier.cpp
    src/stfs/HeaderParser.cpp
    src/stfs/MetadataParser.cpp
    src/stfs/ContainerDetail.cpp
    src/stfs/StfsContainer.cpp
    src/utils/BigUint.cpp
    src/utils/BuildTime.cpp
    src/utils/FileManager.cpp
    src/utils/FusesetGenerator.cpp
    src/utils/Log.cpp
    src/utils/Utils.cpp
    src/utils/XeRsa.cpp
)

# include/ holds only the public API (Library.hpp, GxBuildTypes.hpp); internal headers live
# beside their sources in src/ and stay private, as do GxCrypt and spdlog.
add_library(gxbuild3_lib STATIC ${GXBUILD3_LIB_SOURCES})
target_include_directories(gxbuild3_lib
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/freeboot
)
target_link_libraries(gxbuild3_lib PRIVATE
    GxCrypt
    spdlog::spdlog
)
gxbuild3_enable_warnings(gxbuild3_lib)

# Internal access for the CLI, tests and tools: src/ headers plus the private dependencies.
add_library(gxbuild3_internal INTERFACE)
target_include_directories(gxbuild3_internal INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(gxbuild3_internal INTERFACE
    gxbuild3_lib
    GxCrypt
    spdlog::spdlog
)

# The command-line front end stays out of gxbuild3_lib so library consumers do not carry it.
add_library(gxbuild3_cli STATIC
    src/cli/BuildCommand.cpp
    src/cli/BuildInputResolver.cpp
    src/cli/CommandLine.cpp
)
target_link_libraries(gxbuild3_cli PUBLIC gxbuild3_internal)
gxbuild3_enable_warnings(gxbuild3_cli)

add_executable(gxbuild3 src/Main.cpp)
set_target_properties(gxbuild3 PROPERTIES OUTPUT_NAME gxbuild)
target_link_libraries(gxbuild3 PRIVATE gxbuild3_cli)
gxbuild3_enable_warnings(gxbuild3)

option(GXBUILD3_BUILD_TESTS "Build the gxbuild3 tests" ${PROJECT_IS_TOP_LEVEL})
if(GXBUILD3_BUILD_TESTS)
    include(CTest)
    if(BUILD_TESTING)
        add_subdirectory(tests)
    endif()
endif()

include(GNUInstallDirs)
install(TARGETS gxbuild3 gxbuild3_lib
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES include/Library.hpp include/GxBuildTypes.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gxbuild3
)

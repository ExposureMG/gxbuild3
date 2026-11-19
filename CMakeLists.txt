cmake_minimum_required(VERSION 3.25)
project(GxBuild3 LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(extern/CLI11)
add_subdirectory(extern/GxCrypt)
add_subdirectory(extern/spdlog)
add_subdirectory(extern/stfs)

set(GXBUILD3_LIB_SOURCES
    src/BuildRunner.cpp
    src/GxBuild.cpp
    src/Log.cpp
    src/Options.cpp
    src/Utils.cpp
    src/FlashImage.cpp
    src/utils/FlashBlockDriver.cpp
    src/utils/FusesetGenerator.cpp
    src/ini/IniParser.cpp
    src/patchers/BinaryParser.cpp
    src/patchers/Patcher.cpp
    src/patchers/Signature.cpp
    src/stfs/StfsContainer.cpp
    src/bootloaders/2bl.cpp
    src/bootloaders/3bl.cpp
    src/bootloaders/4bl.cpp
    src/bootloaders/5bl.cpp
    src/bootloaders/6bl.cpp
    src/bootloaders/7bl.cpp
    src/bootloaders/FlashFileSystem.cpp
    src/bootloaders/Keyvault.cpp
    src/bootloaders/SMC.cpp
    src/bootloaders/Xboxupd.cpp
    src/bootloaders/XConfig.cpp
    src/bootloaders/BootloaderPacker.cpp
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
    CLI11::CLI11
    stfs
    GxCrypt
    spdlog::spdlog
)

if(MSVC)
    target_compile_options(gxbuild3_lib PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_options(gxbuild3 PRIVATE /W4 /WX /permissive- /utf-8)
else()
    target_compile_options(gxbuild3_lib PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(gxbuild3 PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

include(GNUInstallDirs)

install(TARGETS gxbuild3 gxbuild3_lib
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

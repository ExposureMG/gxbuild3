# Fetch GoogleTest if a local system package is absent.
find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET)
endif()
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2
        GIT_SHALLOW TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()
include(GoogleTest)

add_executable(gxbuild_crypto_tests
    support/Bytes.cpp
    support/Expect.cpp
    support/Keys.cpp
    core/KeysTests.cpp
    bootloaders/KeyChainTests.cpp
    bootloaders/StageTests.cpp
    objects/KeyvaultVersionTests.cpp
    objects/SecuredFileSealTests.cpp
    objects/FcrtTests.cpp
    utils/RsaTests.cpp
    nand/SmcAndEccTests.cpp
)
target_include_directories(gxbuild_crypto_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gxbuild_crypto_tests PRIVATE gxbuild3_internal GTest::gtest_main)
gxbuild3_enable_warnings(gxbuild_crypto_tests)

gtest_discover_tests(gxbuild_crypto_tests)

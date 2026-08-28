# Include before project(): compiler discovery happens when languages are enabled.
if(CMAKE_GENERATOR MATCHES "Visual Studio")
    message(FATAL_ERROR
        "GxBuild3 requires Clang or GCC with a command-line generator. "
        "Use a fresh build directory with -G Ninja; MSVC is not supported.")
endif()

# Leave explicit compilers, existing caches, environment overrides and toolchains
# to CMake. A parent with one language enabled also needs CMake to infer the
# matching compiler for the other. Otherwise prefer Clang in all search paths.
if(NOT CMAKE_C_COMPILER_LOADED AND NOT CMAKE_CXX_COMPILER_LOADED
        AND NOT CMAKE_TOOLCHAIN_FILE AND "$ENV{CMAKE_TOOLCHAIN_FILE}" STREQUAL "")
    if(NOT CMAKE_C_COMPILER AND "$ENV{CC}" STREQUAL "")
        find_program(CMAKE_C_COMPILER NAMES clang gcc)
        if(NOT CMAKE_C_COMPILER)
            message(FATAL_ERROR "GxBuild3 requires Clang or GCC: install clang or gcc for C.")
        endif()
    endif()
    if(NOT CMAKE_CXX_COMPILER AND "$ENV{CXX}" STREQUAL "")
        find_program(CMAKE_CXX_COMPILER NAMES clang++ g++)
        if(NOT CMAKE_CXX_COMPILER)
            message(FATAL_ERROR "GxBuild3 requires Clang or GCC: install clang++ or g++ for C++.")
        endif()
    endif()
endif()

# Call after project() so explicit overrides and parent projects are checked too.
function(gxbuild3_validate_compilers)
    foreach(language IN ITEMS C CXX)
        if(NOT CMAKE_${language}_COMPILER_ID MATCHES "^(Clang|AppleClang|GNU)$"
                OR CMAKE_${language}_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
            message(FATAL_ERROR
                "GxBuild3 requires Clang or GCC for ${language}; MSVC and clang-cl are not supported. "
                "Configure a fresh build directory with clang/clang++ or gcc/g++.")
        endif()
    endforeach()
endfunction()

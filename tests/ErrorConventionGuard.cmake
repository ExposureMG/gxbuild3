cmake_minimum_required(VERSION 3.29)

# Error-convention guard: library code reports failures through gxbuild3::Result, so the
# exception machinery that remains in src/ and include/ is an explicit, shrinking inventory.
#
#   1. The temporary throwing shims (*_or_throw, value_or_throw) may only be named in the files
#      that define them or still depend on them.
#   2. `throw` may only appear in BigUint (precondition violations) and the shims.
#   3. `catch (...)` may only appear in main().
#
# Every allowlist entry must still match its rule: once a shim is deleted the guard fails until
# the entry is removed, so the allowlists can only shrink. `//` comments are ignored.
#
# Inputs (supplied with -D by the registering add_test()):
#   SOURCE_ROOT  absolute path to the repository root

if(NOT DEFINED SOURCE_ROOT OR NOT IS_DIRECTORY "${SOURCE_ROOT}/src")
    message(FATAL_ERROR "SOURCE_ROOT must name the gxbuild3 repository root")
endif()

# Shim inventory.
#   TODO(test-phase): the bootloader *_or_throw shims (2bl.hpp-7bl.hpp) and their
#     detail::value_or_throw helper (Common.hpp) exist only for the tests; the test rewrite
#     migrates those call sites to the Result API and deletes them.
#   TODO(parsing): stfs::Package (Package.cpp) still throws and unwraps Result helpers through
#     stfs::detail::value_or_throw (PackageCommon.hpp) until the parsing phase converts it.
set(shim_name_allowlist
    src/nand/bootloaders/2bl.hpp
    src/nand/bootloaders/3bl.hpp
    src/nand/bootloaders/4bl.hpp
    src/nand/bootloaders/5bl.hpp
    src/nand/bootloaders/6bl.hpp
    src/nand/bootloaders/7bl.hpp
    src/nand/bootloaders/Common.hpp
    src/stfs/Package.cpp
    src/stfs/PackageCommon.hpp
)

# BigUint throws std::logic_error-family precondition violations by design.
set(throw_allowlist
    src/nand/bootloaders/Common.hpp
    src/stfs/Package.cpp
    src/stfs/PackageCommon.hpp
    src/utils/BigUint.cpp
)

set(catch_all_allowlist
    src/Main.cpp
)

set(rule_shim_name_regex "[A-Za-z0-9_]_or_throw[^A-Za-z0-9_]")
set(rule_throw_regex "[^A-Za-z0-9_]throw[^A-Za-z0-9_]")
set(rule_catch_all_regex "[^A-Za-z0-9_]catch[ \t]*\\([ \t]*\\.\\.\\.[ \t]*\\)")

set(rule_shim_name_label "throwing shim name (*_or_throw / value_or_throw)")
set(rule_throw_label "`throw`")
set(rule_catch_all_label "`catch (...)`")

set(rule_shim_name_allow ${shim_name_allowlist})
set(rule_throw_allow ${throw_allowlist})
set(rule_catch_all_allow ${catch_all_allowlist})

set(rules shim_name throw catch_all)
foreach(rule IN LISTS rules)
    set(hits_${rule} "")
endforeach()

file(GLOB_RECURSE scanned_files RELATIVE "${SOURCE_ROOT}" LIST_DIRECTORIES false
    "${SOURCE_ROOT}/src/*.cpp" "${SOURCE_ROOT}/src/*.hpp" "${SOURCE_ROOT}/src/*.h"
    "${SOURCE_ROOT}/include/*.cpp" "${SOURCE_ROOT}/include/*.hpp" "${SOURCE_ROOT}/include/*.h")
list(SORT scanned_files)
list(LENGTH scanned_files scanned_count)
if(scanned_count EQUAL 0)
    message(FATAL_ERROR "no sources found under ${SOURCE_ROOT}/src")
endif()

set(violations "")
foreach(relative IN LISTS scanned_files)
    file(READ "${SOURCE_ROOT}/${relative}" content)
    # Neutralise the characters that CMake list splitting treats specially, then split on
    # newlines so each list element is one source line.
    string(REPLACE "\\" "_" content "${content}")
    string(REPLACE ";" "_" content "${content}")
    string(REPLACE "[" "_" content "${content}")
    string(REPLACE "]" "_" content "${content}")
    string(REPLACE "\n" ";" lines "${content}")

    set(line_number 0)
    foreach(line IN LISTS lines)
        math(EXPR line_number "${line_number} + 1")
        string(REGEX REPLACE "//.*$" "" code "${line}")
        set(code " ${code} ")
        foreach(rule IN LISTS rules)
            if(NOT code MATCHES "${rule_${rule}_regex}")
                continue()
            endif()
            list(APPEND hits_${rule} "${relative}")
            if(NOT relative IN_LIST rule_${rule}_allow)
                string(STRIP "${line}" shown)
                string(APPEND violations
                    "  ${relative}:${line_number}: ${rule_${rule}_label}: ${shown}\n")
            endif()
        endforeach()
    endforeach()
endforeach()

foreach(rule IN LISTS rules)
    foreach(allowed IN LISTS rule_${rule}_allow)
        if(NOT allowed IN_LIST hits_${rule})
            string(APPEND violations
                "  ${allowed}: stale allowlist entry for ${rule_${rule}_label}; remove it from "
                "tests/ErrorConventionGuard.cmake\n")
        endif()
    endforeach()
endforeach()

if(NOT violations STREQUAL "")
    message(FATAL_ERROR
        "error-convention guard failed (see the Result convention in src/Error.hpp):\n"
        "${violations}")
endif()

message(STATUS "error-convention guard: ${scanned_count} files clean")

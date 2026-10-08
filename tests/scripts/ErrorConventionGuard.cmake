cmake_minimum_required(VERSION 3.29)

# Error-convention guard: library code reports failures through gxbuild3::Result, so the
# exception machinery that remains in src/ and include/ is an explicit, shrinking inventory.
#
#   1. The temporary throwing shims (*_or_throw, value_or_throw) are gone; none may come back.
#   2. `throw` may only appear in BigUint (precondition violations).
#   3. `catch (...)` may only appear in main().
#
# WireConventionGuard (see src/Wire.hpp): on-disk records are plain structs of wire:: field types,
# so the legacy byte-order machinery is a second shrinking inventory.
#   4. `#pragma pack` may only appear in the files that still declare packed records.
#   5. The manual byte-order helpers (bswap16/32/64, read_be*/read_le*, including their
#      __builtin_bswap* bodies, and the deleted swap32) are gone with Endian.hpp; only src/Wire.hpp
#      names bswap*, in the deleted overloads that reject a manual swap on a wire field.
#   6. No file under src/nand/objects/ includes Endian.hpp: every objects record is a wire struct.
# A converting commit removes its file's entry in the same commit.
#
# Every allowlist entry must still match its rule: once a shim is deleted the guard fails until
# the entry is removed, so the allowlists can only shrink. `//` comments are ignored.
#
# Inputs (supplied with -D by the registering add_test()):
#   SOURCE_ROOT  absolute path to the repository root

if(NOT DEFINED SOURCE_ROOT OR NOT IS_DIRECTORY "${SOURCE_ROOT}/src")
    message(FATAL_ERROR "SOURCE_ROOT must name the gxbuild3 repository root")
endif()

# Shim inventory: empty. Tests unwrap Results with ASSERT_OK_AND_ASSIGN (tests/support/Expect.hpp).
set(shim_name_allowlist
)

# BigUint throws std::logic_error-family precondition violations by design.
set(throw_allowlist
    src/utils/BigUint.cpp
)

set(catch_all_allowlist
    src/Main.cpp
)

# WireConventionGuard inventories. XConfig.hpp keeps its packed bitfields on purpose; every other
# entry goes away as its records move to src/Wire.hpp. src/Wire.hpp itself stays: it declares
# the deleted bswap* overloads that reject a manual swap on a wire field.
set(pragma_pack_allowlist
    src/nand/objects/XConfig.hpp
)

set(byte_swap_allowlist
    src/Wire.hpp
)

# No exceptions: objects/ reads and writes on-disk fields only through src/Wire.hpp.
set(objects_endian_include_allowlist
)

set(rule_shim_name_regex "[A-Za-z0-9_]_or_throw[^A-Za-z0-9_]")
set(rule_throw_regex "[^A-Za-z0-9_]throw[^A-Za-z0-9_]")
set(rule_catch_all_regex "[^A-Za-z0-9_]catch[ \t]*\\([ \t]*\\.\\.\\.[ \t]*\\)")
set(rule_pragma_pack_regex "#[ \t]*pragma[ \t]+pack")
# Substring match on purpose: it also catches __builtin_bswap16 and helpers such as
# try_read_be32 that wrap the legacy readers.
set(rule_byte_swap_regex "bswap(16|32|64)|swap32|read_(be|le)(16|24|32|64)")
set(rule_objects_endian_include_regex "#[ \t]*include[ \t]*[\"<]([^\">]*/)?Endian\\.hpp[\">]")

set(rule_shim_name_label "throwing shim name (*_or_throw / value_or_throw)")
set(rule_throw_label "`throw`")
set(rule_catch_all_label "`catch (...)`")
set(rule_pragma_pack_label "`#pragma pack` (use wire:: field types, src/Wire.hpp)")
set(rule_byte_swap_label "manual byte-order helper (use wire:: field types, src/Wire.hpp)")
set(rule_objects_endian_include_label
    "Endian.hpp include under src/nand/objects/ (use wire:: field types, src/Wire.hpp)")

set(rule_shim_name_allow ${shim_name_allowlist})
set(rule_throw_allow ${throw_allowlist})
set(rule_catch_all_allow ${catch_all_allowlist})
set(rule_pragma_pack_allow ${pragma_pack_allowlist})
set(rule_byte_swap_allow ${byte_swap_allowlist})
set(rule_objects_endian_include_allow ${objects_endian_include_allowlist})

# Optional per-rule path scope (a regex on the repository-relative path); unset means every file.
set(rule_objects_endian_include_scope "^src/nand/objects/")

set(rules shim_name throw catch_all pragma_pack byte_swap objects_endian_include)
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
            if(DEFINED rule_${rule}_scope AND NOT relative MATCHES "${rule_${rule}_scope}")
                continue()
            endif()
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
                "tests/scripts/ErrorConventionGuard.cmake\n")
        endif()
    endforeach()
endforeach()

if(NOT violations STREQUAL "")
    message(FATAL_ERROR
        "error-convention guard failed (see the Result convention in src/Error.hpp and the wire "
        "convention in src/Wire.hpp):\n"
        "${violations}")
endif()

message(STATUS "error-convention guard: ${scanned_count} files clean")

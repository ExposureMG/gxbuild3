cmake_minimum_required(VERSION 3.29)

# Golden freeze guard (migration only; deleted with tests/migration/). The GoogleTest migration
# only compares goldens, never writes them: every file in tests/golden must still hash to the
# SHA-256 recorded in tests/migration/golden-baseline.sha256 (sha256sum format, taken from HEAD
# when the migration guards landed), and no golden may be added or removed.
#
# Inputs (-D): GOLDEN_DIR (tests/golden, or a scratch copy for a mutation check), BASELINE.

foreach(input GOLDEN_DIR BASELINE)
    if(NOT DEFINED ${input})
        message(FATAL_ERROR "GoldenFrozen: ${input} is required")
    endif()
endforeach()
if(NOT EXISTS "${BASELINE}")
    message(FATAL_ERROR "GoldenFrozen: baseline ${BASELINE} is missing")
endif()

file(STRINGS "${BASELINE}" lines)
set(expected_names "")
set(problems "")
foreach(line IN LISTS lines)
    if(NOT line MATCHES "^([0-9a-f]+)  (.+)$")
        message(FATAL_ERROR "GoldenFrozen: malformed baseline line: ${line}")
    endif()
    set(hash "${CMAKE_MATCH_1}")
    set(name "${CMAKE_MATCH_2}")
    list(APPEND expected_names "${name}")
    if(NOT EXISTS "${GOLDEN_DIR}/${name}")
        list(APPEND problems "${name}: removed")
        continue()
    endif()
    file(SHA256 "${GOLDEN_DIR}/${name}" actual)
    if(NOT actual STREQUAL hash)
        list(APPEND problems "${name}: sha256 ${actual}, baseline ${hash}")
    endif()
endforeach()

file(GLOB present RELATIVE "${GOLDEN_DIR}" "${GOLDEN_DIR}/*")
foreach(name IN LISTS present)
    if(NOT name IN_LIST expected_names)
        list(APPEND problems "${name}: not in the baseline (goldens are frozen during the migration)")
    endif()
endforeach()

list(LENGTH expected_names count)
if(problems)
    foreach(text IN LISTS problems)
        message("FAIL: tests/golden/${text}")
    endforeach()
    message(FATAL_ERROR "golden_frozen: tests/golden differs from the migration baseline")
endif()
message(STATUS "golden_frozen: ${count}/${count} goldens unchanged")

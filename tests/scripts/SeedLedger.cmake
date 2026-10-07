cmake_minimum_required(VERSION 3.29)

# Seeds the GoogleTest-migration coverage ledger (migration only; deleted with the ledger):
#
#   cmake -DSOURCE_ROOT=. -P tests/scripts/SeedLedger.cmake
#
# writes tests/migration/ledger/<OldFile>.tsv for every old test source (tests/*Tests.cpp plus
# the CliIntegrationTests and MustAbortTest scripts). Each file holds tab-separated rows
#
#   id  old_symbol@line  old_assert_sites  new_test  status[;note:<text>]
#
# with the automatic rows first, every one pending:
#   - one per `(bool|void) test_*(` definition; old_assert_sites counts require( check(
#     check_error( fails_with( require_resolved( must( from the definition to the next
#     top-level definition;
#   - one per namespace-scope static_assert statement (old_symbol static_assert#<sha1-10 of the
#     statement without whitespace>), one per PIN_SIZE/PIN_FIELD invocation and one for
#     BootloaderLayout's pinned-count check in main.
# Hand rows (table rows, main-only checks, script scenarios) follow a `# hand` line and are kept
# verbatim when the seeder runs again. The seeder refuses to touch a ledger that already holds a
# row that is no longer pending, so it cannot undo a port.

if(NOT DEFINED SOURCE_ROOT)
    message(FATAL_ERROR "SOURCE_ROOT must name the gxbuild3 repository root")
endif()
get_filename_component(SOURCE_ROOT "${SOURCE_ROOT}" ABSOLUTE)
if(NOT IS_DIRECTORY "${SOURCE_ROOT}/tests")
    message(FATAL_ERROR "SOURCE_ROOT must name the gxbuild3 repository root")
endif()
include(${CMAKE_CURRENT_LIST_DIR}/LedgerCommon.cmake)

set(ledger_dir "${SOURCE_ROOT}/tests/migration/ledger")
gxbuild3_ledger_old_files(old_files "${SOURCE_ROOT}")

# Refuse first, before anything is written.
foreach(old IN LISTS old_files)
    get_filename_component(base "${old}" NAME_WE)
    set(ledger "${ledger_dir}/${base}.tsv")
    if(EXISTS "${ledger}")
        gxbuild3_ledger_read_lines("${ledger}" rows)
        foreach(row IN LISTS rows)
            if(row STREQUAL "" OR row MATCHES "^#")
                continue()
            endif()
            string(REPLACE "\t" ";" fields "${row}")
            list(GET fields 4 status)
            if(NOT status MATCHES "^pending(@SC@note:.*)?$")
                message(FATAL_ERROR "SeedLedger: ${ledger} already holds a non-pending row "
                    "(${row}); the ledger is seeded once and then only edited by port commits")
            endif()
        endforeach()
    endif()
endforeach()

file(MAKE_DIRECTORY "${ledger_dir}")
set(total_functions 0)
set(total_statics 0)
foreach(old IN LISTS old_files)
    get_filename_component(name "${old}" NAME)
    get_filename_component(base "${old}" NAME_WE)
    gxbuild3_ledger_stem(stem "${name}")
    set(ledger "${ledger_dir}/${base}.tsv")

    set(hand "")
    if(EXISTS "${ledger}")
        file(READ "${ledger}" existing)
        string(FIND "${existing}" "\n# hand\n" at)
        if(at GREATER -1)
            math(EXPR at "${at} + 8")
            string(SUBSTRING "${existing}" ${at} -1 hand)
        endif()
    endif()

    set(out "")
    set(automatic 0)

    if(old MATCHES "\\.cpp$")
        gxbuild3_ledger_scan_source("${SOURCE_ROOT}/${old}")
        foreach(fn IN LISTS LEDGER_FUNCTIONS)
            string(APPEND out
                "${stem}.${fn}\t${fn}@${LEDGER_FN_LINE_${fn}}\t${LEDGER_FN_SITES_${fn}}\t-\tpending\n")
            math(EXPR total_functions "${total_functions} + 1")
        endforeach()
        set(ordinal 0)
        foreach(entry IN LISTS LEDGER_STATIC_ASSERTS)
            string(REPLACE "|" ";" parts "${entry}")
            list(GET parts 0 line)
            list(GET parts 1 digest)
            math(EXPR ordinal "${ordinal} + 1")
            if(ordinal LESS 10)
                set(ordinal "0${ordinal}")
            endif()
            string(APPEND out
                "${stem}.static_assert.${ordinal}\tstatic_assert#${digest}@${line}\t1\t-\tpending\n")
            math(EXPR total_statics "${total_statics} + 1")
        endforeach()
        foreach(entry IN LISTS LEDGER_PINS)
            string(REPLACE "|" ";" parts "${entry}")
            list(GET parts 0 line)
            list(GET parts 1 pin)
            # PIN_FIELD(type,field,0x1C) -> PIN_FIELD.type.field; PIN_SIZE(type,0x10) -> PIN_SIZE.type
            string(REGEX REPLACE "^(PIN_[A-Z]+)\\(([^,]+),([^,)]+),[^)]*\\)$" "\\1.\\2.\\3" id "${pin}")
            string(REGEX REPLACE "^(PIN_SIZE)\\(([^,]+),[^)]*\\)$" "\\1.\\2" id "${id}")
            gxbuild3_ledger_decode(pin "${pin}")
            string(APPEND out "${stem}.${id}\t${pin}@${line}\t1\t-\tpending\n")
            math(EXPR total_statics "${total_statics} + 1")
        endforeach()
        # BootloaderLayout's main compares the pinned record and field counts (10 and 60).
        file(STRINGS "${SOURCE_ROOT}/${old}" count_check REGEX "constexpr int kExpectedRecords")
        if(count_check)
            gxbuild3_ledger_read_lines("${SOURCE_ROOT}/${old}" lines)
            list(FIND lines "    constexpr int kExpectedRecords = 10@SC@" index)
            if(index LESS 0)
                message(FATAL_ERROR "SeedLedger: ${old}: the pinned-count check moved")
            endif()
            math(EXPR line "${index} + 1")
            string(APPEND out "${stem}.pin_count\tkExpectedRecords@${line}\t1\t-\tpending\n")
            math(EXPR total_statics "${total_statics} + 1")
        endif()
    endif()

    # Rows are counted in the header so that a lost row fails the guard; 'new' rows are not.
    string(REGEX MATCHALL "(^|\n)[^#\n][^\n]*" automatic_rows "${out}")
    list(LENGTH automatic_rows automatic)
    string(REPLACE ";" "@SC@" hand_text "${hand}")
    string(REGEX MATCHALL "(^|\n)[^#\n][^\n]*" hand_rows "${hand_text}")
    set(hand_count 0)
    foreach(row IN LISTS hand_rows)
        if(NOT row MATCHES "\tnew(@SC@note:.*)?$")
            math(EXPR hand_count "${hand_count} + 1")
        endif()
    endforeach()
    set(header "# Coverage ledger for ${old} (GoogleTest migration; see tests/scripts/CoverageLedger.cmake).\n")
    string(APPEND header "# rows: ${automatic} automatic, ${hand_count} hand. Port commits change statuses and never delete a row; rows with status new are not counted.\n")
    string(APPEND header "# Seeded by tests/scripts/SeedLedger.cmake. Columns, tab-separated:\n")
    string(APPEND header "# id\told_symbol@line\told_assert_sites\tnew_test\tstatus[;note:<text>]\n")
    file(WRITE "${ledger}" "${header}${out}# hand\n${hand}")
endforeach()

list(LENGTH old_files files)
message(STATUS "SeedLedger: ${files} ledgers, ${total_functions} function rows, "
    "${total_statics} static_assert rows in ${ledger_dir}")

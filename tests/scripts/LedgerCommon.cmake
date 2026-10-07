# Helpers shared by SeedLedger.cmake and CoverageLedger.cmake (migration only): line-safe source
# reading, the old test-source scan that yields the automatic ledger rows, and the ledger parser.
#
# CMake lists split on ';' and group on '[' ']', and a trailing '\' escapes the separator, so
# every line is read with those four characters encoded (@SC@ @LB@ @RB@ @BS@) and decoded only
# where the text itself matters (statement fingerprints).

include_guard(GLOBAL)

# Assertion sites of an old test function: the hand-rolled helpers every old binary used.
set(GXBUILD3_LEDGER_SITE_REGEX "(require|check|check_error|fails_with|require_resolved|must)\\(")
set(GXBUILD3_LEDGER_FUNCTION_REGEX "^[ ]*(bool|void)[ ]+(test_[A-Za-z0-9_]+)\\(")

# gxbuild3_ledger_read_lines(<path> <out-list>)
function(gxbuild3_ledger_read_lines path out)
    file(READ "${path}" content)
    string(REPLACE "\r" "" content "${content}")
    string(REPLACE "\\" "@BS@" content "${content}")
    string(REPLACE ";" "@SC@" content "${content}")
    string(REPLACE "[" "@LB@" content "${content}")
    string(REPLACE "]" "@RB@" content "${content}")
    string(REPLACE "\n" ";" lines "${content}")
    set(${out} "${lines}" PARENT_SCOPE)
endfunction()

# gxbuild3_ledger_decode(<out> <text>): undo the encoding of gxbuild3_ledger_read_lines.
function(gxbuild3_ledger_decode out text)
    string(REPLACE "@SC@" ";" text "${text}")
    string(REPLACE "@LB@" "[" text "${text}")
    string(REPLACE "@RB@" "]" text "${text}")
    string(REPLACE "@BS@" "\\" text "${text}")
    set(${out} "${text}" PARENT_SCOPE)
endfunction()

# gxbuild3_ledger_count_sites(<out> <line>): occurrences of an assertion helper call that is not
# the tail of a longer identifier (the \b of the plan's grep).
function(gxbuild3_ledger_count_sites out line)
    set(n 0)
    if(line MATCHES "${GXBUILD3_LEDGER_SITE_REGEX}")
        string(REGEX REPLACE "[A-Za-z0-9_]${GXBUILD3_LEDGER_SITE_REGEX}" "" line "${line}")
        string(REGEX MATCHALL "${GXBUILD3_LEDGER_SITE_REGEX}" hits "${line}")
        list(LENGTH hits n)
    endif()
    set(${out} ${n} PARENT_SCOPE)
endfunction()

# gxbuild3_ledger_scan_source(<path>) sets in the caller's scope:
#   LEDGER_FUNCTIONS        test_* function names in source order
#   LEDGER_FN_LINE_<name>   1-based line of the definition
#   LEDGER_FN_SITES_<name>  assertion sites from that line to the next top-level definition
#   LEDGER_STATIC_ASSERTS   "<line>|<sha1-10>" for each namespace-scope static_assert statement
#                           (not inside a test_ function, not part of a #define body); the hash
#                           is over the statement with all whitespace removed
#   LEDGER_PINS             "<line>|<PIN_SIZE(...)|PIN_FIELD(...)>" invocations, whitespace removed
# A function's span ends at the first later non-blank line indented no deeper than its signature
# that is not a closing brace or a preprocessor line (sources are clang-formatted).
function(gxbuild3_ledger_scan_source path)
    gxbuild3_ledger_read_lines("${path}" lines)
    set(functions "")
    set(statics "")
    set(pins "")
    set(open "")
    set(open_indent 0)
    set(open_sites 0)
    set(in_static FALSE)
    set(static_text "")
    set(static_line 0)
    set(number 0)
    foreach(line IN LISTS lines)
        math(EXPR number "${number} + 1")
        if(open)
            if(line MATCHES "^([ ]*)([^ }#])")
                string(LENGTH "${CMAKE_MATCH_1}" indent)
                if(NOT indent GREATER open_indent)
                    set(LEDGER_FN_SITES_${open} ${open_sites} PARENT_SCOPE)
                    set(open "")
                endif()
            endif()
        endif()
        if(line MATCHES "${GXBUILD3_LEDGER_FUNCTION_REGEX}")
            set(open "${CMAKE_MATCH_2}")
            string(REGEX MATCH "^[ ]*" lead "${line}")
            string(LENGTH "${lead}" open_indent)
            set(open_sites 0)
            list(APPEND functions "${open}")
            set(LEDGER_FN_LINE_${open} ${number} PARENT_SCOPE)
        endif()
        if(open)
            gxbuild3_ledger_count_sites(n "${line}")
            math(EXPR open_sites "${open_sites} + ${n}")
        elseif(NOT in_static AND line MATCHES "^[ ]*static_assert\\(" AND
               NOT line MATCHES "@BS@[ ]*$")
            set(in_static TRUE)
            set(static_text "")
            set(static_line ${number})
        elseif(line MATCHES "^[ ]*(PIN_(SIZE|FIELD)\\([^)]*\\))@SC@")
            string(REGEX REPLACE "[ \t]" "" pin "${CMAKE_MATCH_1}")
            list(APPEND pins "${number}|${pin}")
        endif()
        if(in_static)
            string(APPEND static_text "${line}")
            if(line MATCHES "@SC@[ ]*$")
                gxbuild3_ledger_decode(statement "${static_text}")
                string(REGEX REPLACE "[ \t]" "" statement "${statement}")
                string(SHA1 digest "${statement}")
                string(SUBSTRING "${digest}" 0 10 digest)
                list(APPEND statics "${static_line}|${digest}")
                set(in_static FALSE)
            endif()
        endif()
    endforeach()
    if(open)
        set(LEDGER_FN_SITES_${open} ${open_sites} PARENT_SCOPE)
    endif()
    set(LEDGER_FUNCTIONS "${functions}" PARENT_SCOPE)
    set(LEDGER_STATIC_ASSERTS "${statics}" PARENT_SCOPE)
    set(LEDGER_PINS "${pins}" PARENT_SCOPE)
endfunction()

# gxbuild3_ledger_stem(<out> <old file name>): BuildRunnerTests.cpp -> BuildRunner,
# MustAbortTest.cmake -> MustAbort.
function(gxbuild3_ledger_stem out name)
    string(REGEX REPLACE "\\.(cpp|cmake)$" "" stem "${name}")
    string(REGEX REPLACE "Tests?$" "" stem "${stem}")
    set(${out} "${stem}" PARENT_SCOPE)
endfunction()

# gxbuild3_ledger_old_files(<out> <source root>): the old test sources, one ledger each.
function(gxbuild3_ledger_old_files out root)
    file(GLOB cpp RELATIVE "${root}" "${root}/tests/*Tests.cpp")
    list(SORT cpp)
    set(${out} ${cpp} tests/scripts/CliIntegrationTests.cmake tests/scripts/MustAbortTest.cmake
        PARENT_SCOPE)
endfunction()

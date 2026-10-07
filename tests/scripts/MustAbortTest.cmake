# Checks that gxbuild3::test::must() (tests/TestResult.hpp) aborts on a failed Result and
# reports Error::describe() with the call site. Runs tools/MustAbortDemo.cpp in its
# --must-abort-demo mode once per overload.
#
# Required: -DGXBUILD3_SELFTEST=<path to gxbuild3_must_abort_demo>

if(NOT GXBUILD3_SELFTEST)
    message(FATAL_ERROR "GXBUILD3_SELFTEST is not set")
endif()

set(checked 0)
foreach(overload value void)
    if(overload STREQUAL "void")
        set(demo_args --must-abort-demo void)
        set(expected_message "planted void failure")
    else()
        set(demo_args --must-abort-demo)
        set(expected_message "outer: inner: planted failure")
    endif()

    execute_process(
        COMMAND "${GXBUILD3_SELFTEST}" ${demo_args}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE out
        ERROR_VARIABLE err)

    if(result STREQUAL "0")
        message(FATAL_ERROR "must() ${overload} overload: the demo exited 0; it must abort\n${err}")
    endif()
    if(NOT err MATCHES "must\\(\\) failed at [^\n]*MustAbortDemo\\.cpp:[0-9]+ in ")
        message(FATAL_ERROR "must() ${overload} overload: no call site on stderr\n${err}")
    endif()
    string(FIND "${err}" ": ${expected_message}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
            "must() ${overload} overload: stderr lacks Error::describe() '${expected_message}'\n${err}")
    endif()
    if(err MATCHES "must\\(\\) returned")
        message(FATAL_ERROR "must() ${overload} overload: returned on a failed Result\n${err}")
    endif()
    message(STATUS "must() ${overload} overload aborted (${result}): ${err}")
    math(EXPR checked "${checked} + 1")
endforeach()

message(STATUS "must() abort checks: ${checked}/2")

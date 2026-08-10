if(NOT DEFINED AIRECE_EXE OR NOT DEFINED FIXTURE)
    message(FATAL_ERROR "AIRECE_EXE and FIXTURE are required")
endif()

execute_process(
    COMMAND "${AIRECE_EXE}" vars "${FIXTURE}" 0x140001000 --profile fast
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE diagnostics)
if(NOT result EQUAL 0 AND NOT result EQUAL 3)
    message(FATAL_ERROR
        "vars failed with ${result}\nstdout:\n${output}\nstderr:\n${diagnostics}")
endif()
if(NOT diagnostics STREQUAL "")
    message(FATAL_ERROR "diagnostics leaked for valid variable request: ${diagnostics}")
endif()
foreach(expected IN ITEMS
        "arg0:unknown<64> kind=argument id=value:"
        "call_sub_140001013_result:unknown<64> kind=call-result id=value:"
        "confidence=")
    string(FIND "${output}" "${expected}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "variable output is missing '${expected}':\n${output}")
    endif()
endforeach()

execute_process(
    COMMAND "${AIRECE_EXE}" vars "${FIXTURE}" 0x140001000 --max-variables 1
    RESULT_VARIABLE bounded_result
    OUTPUT_VARIABLE bounded_output
    ERROR_VARIABLE bounded_diagnostics)
if(NOT bounded_result EQUAL 3 OR NOT bounded_diagnostics STREQUAL "")
    message(FATAL_ERROR
        "bounded vars contract failed with ${bounded_result}\n"
        "stdout:\n${bounded_output}\nstderr:\n${bounded_diagnostics}")
endif()
string(REGEX MATCHALL "\n" newlines "${bounded_output}")
list(LENGTH newlines line_count)
if(NOT line_count EQUAL 1)
    message(FATAL_ERROR "bounded vars did not emit exactly one line:\n${bounded_output}")
endif()

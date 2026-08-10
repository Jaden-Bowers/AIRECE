if(NOT DEFINED AIRECE_EXE OR NOT DEFINED FIXTURE OR NOT DEFINED COMMAND_NAME)
    message(FATAL_ERROR "AIRECE_EXE, FIXTURE, and COMMAND_NAME are required")
endif()

execute_process(
    COMMAND "${AIRECE_EXE}" "${COMMAND_NAME}" "${FIXTURE}" --profile fast
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE diagnostics)

if(NOT result EQUAL 0 AND NOT result EQUAL 3)
    message(FATAL_ERROR
        "${COMMAND_NAME} failed with ${result}\nstdout:\n${output}\nstderr:\n${diagnostics}")
endif()
if(NOT diagnostics STREQUAL "")
    message(FATAL_ERROR "diagnostics leaked for valid input: ${diagnostics}")
endif()

if(COMMAND_NAME STREQUAL "inspect")
    foreach(expected IN ITEMS
            "format: pe"
            "arch: x86_64"
            "functions:"
            "completeness:"
            "symbolic-context: not-initialized"
            "solver: not-initialized")
        string(FIND "${output}" "${expected}" found)
        if(found EQUAL -1)
            message(FATAL_ERROR "inspect output is missing '${expected}':\n${output}")
        endif()
    endforeach()
elseif(COMMAND_NAME STREQUAL "functions")
    if(NOT output MATCHES "0x[0-9a-f]+ sub_[0-9a-f]+ coverage=")
        message(FATAL_ERROR "function output is not deterministic inventory text:\n${output}")
    endif()
else()
    message(FATAL_ERROR "unsupported test command: ${COMMAND_NAME}")
endif()

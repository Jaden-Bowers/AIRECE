if(NOT DEFINED AIRECE_EXE OR NOT DEFINED FIXTURE)
    message(FATAL_ERROR "AIRECE_EXE and FIXTURE are required")
endif()

execute_process(
    COMMAND "${AIRECE_EXE}" expr "${FIXTURE}" 0x0 --profile fast
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE diagnostics)

if(NOT result EQUAL 0 AND NOT result EQUAL 3)
    message(FATAL_ERROR
        "expr failed with ${result}\nstdout:\n${output}\nstderr:\n${diagnostics}")
endif()
if(NOT diagnostics STREQUAL "")
    message(FATAL_ERROR "diagnostics leaked for valid expression: ${diagnostics}")
endif()
if(NOT output STREQUAL "rax\n")
    message(FATAL_ERROR "expression output is not deterministic: ${output}")
endif()

execute_process(
    COMMAND "${AIRECE_EXE}" expr "${FIXTURE}" 0 --max-expression-characters 1
    RESULT_VARIABLE bounded_result
    OUTPUT_VARIABLE bounded_output
    ERROR_VARIABLE bounded_diagnostics)
if(NOT bounded_result EQUAL 3 OR NOT bounded_output STREQUAL ".\n" OR
   NOT bounded_diagnostics STREQUAL "")
    message(FATAL_ERROR
        "bounded expr contract failed with ${bounded_result}\n"
        "stdout:\n${bounded_output}\nstderr:\n${bounded_diagnostics}")
endif()

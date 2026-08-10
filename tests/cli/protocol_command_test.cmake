if(NOT DEFINED AIRECE_EXE OR NOT DEFINED FIXTURE)
    message(FATAL_ERROR "AIRECE_EXE and FIXTURE are required")
endif()

execute_process(COMMAND "${AIRECE_EXE}" fn "${FIXTURE}" 0x140001000 --view json
    RESULT_VARIABLE _json_result OUTPUT_VARIABLE _json ERROR_VARIABLE _json_error)
if(NOT _json_result EQUAL 0 AND NOT _json_result EQUAL 3)
    message(FATAL_ERROR "json command failed: ${_json_error}")
endif()
if(NOT _json_error STREQUAL "")
    message(FATAL_ERROR "json diagnostics leaked to stderr: ${_json_error}")
endif()
foreach(_required IN ITEMS "\"schema\":\"airece.semantic.v1\"" "\"statements\"" "\"evidence\"")
    string(FIND "${_json}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "json output lacks ${_required}: ${_json}")
    endif()
endforeach()

# Every successful JSON command must produce a valid JSON document, even when
# the requested budget cannot hold the semantic schema.  A one-byte budget is
# impossible and must fail with an actionable stderr diagnostic.
execute_process(COMMAND "${AIRECE_EXE}" fn "${FIXTURE}" 0x140001000 --view json
    --max-bytes 2
    RESULT_VARIABLE _tiny_json_result OUTPUT_VARIABLE _tiny_json
    ERROR_VARIABLE _tiny_json_error)
if(NOT _tiny_json_result EQUAL 3 OR NOT _tiny_json STREQUAL "{}")
    message(FATAL_ERROR "two-byte JSON budget must return valid {}: result=${_tiny_json_result} output=${_tiny_json} error=${_tiny_json_error}")
endif()

execute_process(COMMAND "${AIRECE_EXE}" fn "${FIXTURE}" 0x140001000 --view json
    --max-bytes 1
    RESULT_VARIABLE _impossible_json_result OUTPUT_VARIABLE _impossible_json
    ERROR_VARIABLE _impossible_json_error)
if(NOT _impossible_json_result EQUAL 1 OR NOT _impossible_json STREQUAL "")
    message(FATAL_ERROR "one-byte JSON budget must fail with empty stdout")
endif()
string(FIND "${_impossible_json_error}" "at least 2 bytes" _tiny_error_found)
if(_tiny_error_found EQUAL -1)
    message(FATAL_ERROR "impossible JSON budget diagnostic missing: ${_impossible_json_error}")
endif()

set(_malformed "${CMAKE_CURRENT_BINARY_DIR}/airece-phase9-malformed.bin")
file(WRITE "${_malformed}" "not-a-valid-executable")
execute_process(COMMAND "${AIRECE_EXE}" inspect "${_malformed}"
    --max-input-bytes 64 --max-wall-time-ms 100
    RESULT_VARIABLE _bad_result OUTPUT_VARIABLE _bad_output ERROR_VARIABLE _bad_error
    TIMEOUT 5)
if(NOT _bad_result EQUAL 1 OR NOT _bad_output STREQUAL "")
    message(FATAL_ERROR "malformed input must fail bounded with empty stdout")
endif()
string(FIND "${_bad_error}" "airece:" _bad_found)
if(_bad_found EQUAL -1)
    message(FATAL_ERROR "malformed input diagnostic missing: ${_bad_error}")
endif()
file(REMOVE "${_malformed}")

execute_process(COMMAND "${AIRECE_EXE}" fn "${FIXTURE}" 0x140001000 --view ir
    RESULT_VARIABLE _ir_result OUTPUT_VARIABLE _ir ERROR_VARIABLE _ir_error)
if(NOT _ir_result EQUAL 0 AND NOT _ir_result EQUAL 3)
    message(FATAL_ERROR "ir command failed: ${_ir_error}")
endif()
foreach(_required IN ITEMS "xair-function 0" "op0" "term kind=")
    string(FIND "${_ir}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "IR output lacks ${_required}: ${_ir}")
    endif()
endforeach()

execute_process(COMMAND "${AIRECE_EXE}" fn "${FIXTURE}" 0x140001000 --view json
    --symbolic --max-queries 2 --max-states 16 --symbolic-timeout-ms 100
    RESULT_VARIABLE _sym_result OUTPUT_VARIABLE _sym ERROR_VARIABLE _sym_error)
if(NOT _sym_result EQUAL 0 AND NOT _sym_result EQUAL 3)
    message(FATAL_ERROR "symbolic command failed: ${_sym_error}")
endif()
foreach(_required IN ITEMS "\"enrichment\"" "expression v14 constant?" "XAIR-proven; presentation unchanged")
    string(FIND "${_sym}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "symbolic output lacks ${_required}: ${_sym}")
    endif()
endforeach()

foreach(_command IN ITEMS calls xrefs slice evidence path taint)
    if(_command STREQUAL "calls")
        set(_args calls "${FIXTURE}" 0x140001000)
        set(_needle "owner=0")
    elseif(_command STREQUAL "xrefs")
        set(_args xrefs "${FIXTURE}" 0x140001013)
        set(_needle "call 0x14000100e")
    elseif(_command STREQUAL "slice")
        set(_args slice "${FIXTURE}" 0x14000100e)
        set(_needle "F140001000:S:O16")
    elseif(_command STREQUAL "evidence")
        set(_args evidence "${FIXTURE}" F140001000:S:O16)
        set(_needle "evidence=F140001000:E:O16")
    elseif(_command STREQUAL "path")
        set(_args path "${FIXTURE}" --from 0x140001000 --to 0x140001010 --max-states 32)
        set(_needle "path n0")
    else()
        set(_args taint "${FIXTURE}" 0x140001000 --max-states 32 --symbolic-timeout-ms 100)
        set(_needle "solver=not-initialized")
    endif()
    execute_process(COMMAND "${AIRECE_EXE}" ${_args}
        RESULT_VARIABLE _result OUTPUT_VARIABLE _output ERROR_VARIABLE _error)
    if(NOT _result EQUAL 0 AND NOT _result EQUAL 3)
        message(FATAL_ERROR "${_command} failed (${_result}): ${_error}")
    endif()
    string(FIND "${_output}" "${_needle}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "${_command} lacks ${_needle}: ${_output}")
    endif()
endforeach()

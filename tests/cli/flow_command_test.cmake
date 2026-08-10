if(NOT DEFINED AIRECE_EXE OR NOT DEFINED FIXTURE)
    message(FATAL_ERROR "AIRECE_EXE and FIXTURE are required")
endif()

set(_base "${AIRECE_EXE}" flow "${FIXTURE}"
    --source "arg=register(rcx)@0x14000100e:before"
    --target "callee=funcarg(0)@0x140001013")
execute_process(COMMAND ${_base}
    RESULT_VARIABLE _plain_result OUTPUT_VARIABLE _plain ERROR_VARIABLE _plain_error)
if(NOT _plain_result EQUAL 0 AND NOT _plain_result EQUAL 3)
    message(FATAL_ERROR "plain flow failed (${_plain_result}): ${_plain_error}")
endif()
foreach(_required IN ITEMS "mode=taint" "verdict=may-flow" "function-depth-limit=3"
        "solver=not-initialized" "call-depth=1" "values=v21" "values=v37")
    string(FIND "${_plain}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "plain flow lacks '${_required}': ${_plain}")
    endif()
endforeach()

execute_process(COMMAND ${_base} --function-depth 0
    RESULT_VARIABLE _local_result OUTPUT_VARIABLE _local ERROR_VARIABLE _local_error)
if(NOT _local_result EQUAL 0 AND NOT _local_result EQUAL 3)
    message(FATAL_ERROR "local flow failed (${_local_result}): ${_local_error}")
endif()
string(FIND "${_local}" "influence source=" _local_flow)
if(NOT _local_flow EQUAL -1)
    message(FATAL_ERROR "depth zero crossed a function boundary: ${_local}")
endif()
string(FIND "${_local}" "function-depth-limit=0" _local_depth)
if(_local_depth EQUAL -1)
    message(FATAL_ERROR "depth-zero output lacks its effective bound: ${_local}")
endif()

execute_process(COMMAND ${_base} --target "result=callresult@0x14000100e"
    --max-paths 1
    RESULT_VARIABLE _return_result OUTPUT_VARIABLE _return ERROR_VARIABLE _return_error)
if(NOT _return_result EQUAL 0 AND NOT _return_result EQUAL 3)
    message(FATAL_ERROR "cross-call return flow failed (${_return_result}): ${_return_error}")
endif()
foreach(_required IN ITEMS "verdict=may-flow" "paths=1" "call-return")
    string(FIND "${_return}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "cross-call return flow lacks '${_required}': ${_return}")
    endif()
endforeach()

execute_process(COMMAND "${AIRECE_EXE}" flow "${FIXTURE}"
    --source "x=register(rax)@0x140001000:before"
    --target "callee=callarg(0)@0x14000100e" --max-paths 1
    RESULT_VARIABLE _negative_result OUTPUT_VARIABLE _negative ERROR_VARIABLE _negative_error)
if(NOT _negative_result EQUAL 0 AND NOT _negative_result EQUAL 3)
    message(FATAL_ERROR "negative flow failed (${_negative_result}): ${_negative_error}")
endif()
string(FIND "${_negative}" "influence source=" _negative_flow)
if(NOT _negative_flow EQUAL -1)
    message(FATAL_ERROR "negative flow produced a data influence: ${_negative}")
endif()

execute_process(COMMAND ${_base} --json
    RESULT_VARIABLE _json_result OUTPUT_VARIABLE _json ERROR_VARIABLE _json_error)
if(NOT _json_result EQUAL 0 AND NOT _json_result EQUAL 3)
    message(FATAL_ERROR "JSON flow failed (${_json_result}): ${_json_error}")
endif()
foreach(_required IN ITEMS "\"schema\":\"airece.flow.v1\"" "\"function_depth\":3"
        "\"verdict\":\"may-flow\"" "\"solver_initialized\":false")
    string(FIND "${_json}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "JSON flow lacks '${_required}': ${_json}")
    endif()
endforeach()

execute_process(COMMAND "${AIRECE_EXE}" flow "${FIXTURE}"
    --source "x=register(rax)@0x140001000:before"
    --target "goal=reach@0x14000100e" --mode taint-symbolic
    --symbolic-timeout-ms 1000
    RESULT_VARIABLE _sym_result OUTPUT_VARIABLE _sym ERROR_VARIABLE _sym_error)
if(NOT _sym_result EQUAL 0 AND NOT _sym_result EQUAL 3)
    message(FATAL_ERROR "symbolic flow failed (${_sym_result}): ${_sym_error}")
endif()
foreach(_required IN ITEMS "verdict=feasible-flow" "constraint rax == rbx"
        "source-constrained=yes" "solver=initialized" "witness source=0")
    string(FIND "${_sym}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "symbolic flow lacks '${_required}': ${_sym}")
    endif()
endforeach()

execute_process(COMMAND "${AIRECE_EXE}" flow "${FIXTURE}"
    --source "bad=buffer(rcx,0)@0x14000100e"
    --target "goal=reach@0x140001013"
    RESULT_VARIABLE _bad_result OUTPUT_VARIABLE _bad_output ERROR_VARIABLE _bad_error)
if(NOT _bad_result EQUAL 2 OR NOT _bad_output STREQUAL "")
    message(FATAL_ERROR "invalid selector must be a usage error with empty stdout")
endif()
string(FIND "${_bad_error}" "invalid source selector" _bad_found)
if(_bad_found EQUAL -1)
    message(FATAL_ERROR "invalid selector diagnostic missing: ${_bad_error}")
endif()

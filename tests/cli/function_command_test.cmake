if(NOT DEFINED AIRECE_EXE OR NOT DEFINED FIXTURE)
    message(FATAL_ERROR "AIRECE_EXE and FIXTURE are required")
endif()

set(_base "${AIRECE_EXE}" fn "${FIXTURE}" 0x140001000 --profile fast)
execute_process(
    COMMAND ${_base} --view compact
    RESULT_VARIABLE _compact_result
    OUTPUT_VARIABLE _compact
    ERROR_VARIABLE _compact_error)
if(NOT _compact_result EQUAL 0 AND NOT _compact_result EQUAL 3)
    message(FATAL_ERROR "compact fn failed (${_compact_result}): ${_compact_error}")
endif()
foreach(_required IN ITEMS "fn 0x140001000" "coverage:" "control:" "calls:" "evidence:")
    string(FIND "${_compact}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "compact fn output lacks '${_required}':\n${_compact}")
    endif()
endforeach()

execute_process(
    COMMAND ${_base} --view compact
    RESULT_VARIABLE _repeat_result
    OUTPUT_VARIABLE _repeat
    ERROR_VARIABLE _repeat_error)
if(NOT _repeat_result EQUAL _compact_result OR NOT _repeat STREQUAL _compact)
    message(FATAL_ERROR "compact fn output is not byte-deterministic")
endif()

execute_process(
    COMMAND ${_base} --view pseudo --max-bytes 2500
    RESULT_VARIABLE _pseudo_result
    OUTPUT_VARIABLE _pseudo
    ERROR_VARIABLE _pseudo_error)
if(NOT _pseudo_result EQUAL 0 AND NOT _pseudo_result EQUAL 3)
    message(FATAL_ERROR "pseudo fn failed (${_pseudo_result}): ${_pseudo_error}")
endif()
foreach(_required IN ITEMS "if (" "F140001000_L" "goto F140001000_L")
    string(FIND "${_pseudo}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "pseudo output lacks '${_required}':\n${_pseudo}")
    endif()
endforeach()

execute_process(
    COMMAND ${_base} --view disassembly --max-bytes 700 --max-statements 3
    RESULT_VARIABLE _disassembly_result
    OUTPUT_VARIABLE _disassembly
    ERROR_VARIABLE _disassembly_error)
if(NOT _disassembly_result EQUAL 0 AND NOT _disassembly_result EQUAL 3)
    message(FATAL_ERROR "disassembly fn failed (${_disassembly_result}): ${_disassembly_error}")
endif()
foreach(_required IN ITEMS "0x140001000:" "omitted-instructions:")
    string(FIND "${_disassembly}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "disassembly output lacks '${_required}':\n${_disassembly}")
    endif()
endforeach()
string(LENGTH "${_disassembly}" _disassembly_length)
if(_disassembly_length GREATER 700)
    message(FATAL_ERROR "disassembly output exceeds byte budget: ${_disassembly_length}")
endif()

execute_process(
    COMMAND ${_base} --view compact --max-bytes 220 --max-statements 1 --max-evidence 1
    RESULT_VARIABLE _bounded_result
    OUTPUT_VARIABLE _bounded
    ERROR_VARIABLE _bounded_error)
if(NOT _bounded_result EQUAL 3)
    message(FATAL_ERROR "bounded fn should be partial, got ${_bounded_result}: ${_bounded_error}")
endif()
foreach(_required IN ITEMS "omitted:" "continue-with:")
    string(FIND "${_bounded}" "${_required}" _found)
    if(_found EQUAL -1)
        message(FATAL_ERROR "bounded output lacks '${_required}':\n${_bounded}")
    endif()
endforeach()
string(LENGTH "${_bounded}" _bounded_length)
if(_bounded_length GREATER 732)
    message(FATAL_ERROR "bounded output exceeds byte budget plus footer: ${_bounded_length}")
endif()

execute_process(
    COMMAND ${_base} --no-ir
    RESULT_VARIABLE _no_ir_result
    OUTPUT_VARIABLE _no_ir_output
    ERROR_VARIABLE _no_ir_error)
if(NOT _no_ir_result EQUAL 2 OR NOT _no_ir_output STREQUAL "")
    message(FATAL_ERROR "fn --no-ir must fail as usage without stdout")
endif()
string(FIND "${_no_ir_error}" "requires IR construction" _no_ir_found)
if(_no_ir_found EQUAL -1)
    message(FATAL_ERROR "fn --no-ir diagnostic missing: ${_no_ir_error}")
endif()

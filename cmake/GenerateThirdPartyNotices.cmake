if(NOT DEFINED AIRECE_NOTICE_OUTPUT)
    message(FATAL_ERROR "AIRECE_NOTICE_OUTPUT is required")
endif()

set(_notice "# AIRECE third-party notices\n\n")
string(APPEND _notice "Generated from the dependency licenses selected by the pinned build.\n")

foreach(_component IN ITEMS XAIR XAIR_CFG XAIR_SYM ZYDIS ZYCORE Z3)
    set(_license "${AIRECE_NOTICE_${_component}}")
    if(NOT EXISTS "${_license}")
        message(FATAL_ERROR "Missing ${_component} license: ${_license}")
    endif()
    file(READ "${_license}" _license_text)
    string(APPEND _notice "\n## ${_component}\n\n```text\n${_license_text}\n```\n")
endforeach()

file(WRITE "${AIRECE_NOTICE_OUTPUT}" "${_notice}")

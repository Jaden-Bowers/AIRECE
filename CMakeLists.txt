cmake_minimum_required(VERSION 3.25)

if(POLICY CMP0184)
    cmake_policy(SET CMP0184 NEW)
endif()

project(AIRECE VERSION 0.11.0 LANGUAGES C CXX)

# This identifier is intentionally independent of the semantic/flow schema
# versions.  Benchmark reports require it so results cannot silently mix
# binaries built before and after the release-candidate freeze.
set(AIRECE_BENCHMARK_FREEZE "v0.11.0-platform-rc1")

# CMake projects configured before CMP0184 may retain /RTC1 in cached Debug
# flags.  Move that setting to the target property so the CRT-free compiler
# fixture can explicitly opt out while normal Debug targets keep the default.
if(POLICY CMP0184)
    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
endif()

include(CTest)
include(GNUInstallDirs)
include(cmake/DependencyPins.cmake)

option(AIRECE_ENFORCE_DEPENDENCY_PINS
    "Fail configuration when component HEADs differ from the recorded pins" ON)
option(AIRECE_ALLOW_DIRTY_DEPENDENCIES
    "Allow uncommitted dependency changes in an explicitly opted-in development build" OFF)
option(AIRECE_STATIC_MSVC_RUNTIME
    "Link the Windows C/C++ runtime statically" ON)

if(MSVC AND AIRECE_STATIC_MSVC_RUNTIME)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(AIRECE_STATIC_RUNTIME_TEXT "yes")
else()
    set(AIRECE_STATIC_RUNTIME_TEXT "no")
endif()

if(MSVC)
    # Z3 enables parallel compilation for large targets. Serialize access to
    # each target's compiler PDB so Debug builds cannot fail with C1041.
    add_compile_options(
        "$<$<COMPILE_LANG_AND_ID:C,MSVC>:/FS>"
        "$<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/FS>")
endif()

function(airece_default_dependency variable vendored sibling)
    if(EXISTS "${vendored}/CMakeLists.txt")
        set(${variable} "${vendored}" CACHE PATH "Source directory for ${variable}")
    else()
        set(${variable} "${sibling}" CACHE PATH "Source directory for ${variable}")
    endif()
endfunction()

airece_default_dependency(AIRECE_XAIR_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/xair"
    "${CMAKE_CURRENT_SOURCE_DIR}/../IR/xair")
airece_default_dependency(AIRECE_XAIR_CFG_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/xair_cfg"
    "${CMAKE_CURRENT_SOURCE_DIR}/../IR/xair_cfg")
airece_default_dependency(AIRECE_XAIR_SYM_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/xair_sym"
    "${CMAKE_CURRENT_SOURCE_DIR}/../IR/xair_sym")

set(AIRECE_ZYDIS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/zydis"
    CACHE PATH "Pinned Zydis source directory")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/z3-source/CMakeLists.txt")
    set(_airece_z3_default "${CMAKE_CURRENT_SOURCE_DIR}/vendor/z3-source")
else()
    set(_airece_z3_default
        "${CMAKE_CURRENT_SOURCE_DIR}/../IR/qualification-private/release/linux/dependencies-a/z3-src")
endif()
set(AIRECE_Z3_SOURCE_DIR "${_airece_z3_default}"
    CACHE PATH "Pinned Z3 source directory")

foreach(_source IN ITEMS
        AIRECE_XAIR_SOURCE_DIR
        AIRECE_XAIR_CFG_SOURCE_DIR
        AIRECE_XAIR_SYM_SOURCE_DIR
        AIRECE_ZYDIS_SOURCE_DIR
        AIRECE_Z3_SOURCE_DIR)
    if(NOT EXISTS "${${_source}}/CMakeLists.txt")
        message(FATAL_ERROR "${_source} does not contain CMakeLists.txt: ${${_source}}")
    endif()
endforeach()

function(airece_git_revision source expected output)
    execute_process(
        COMMAND git -c core.filemode=false -c core.autocrlf=true
            -C "${source}" rev-parse HEAD
        RESULT_VARIABLE _git_result
        OUTPUT_VARIABLE _revision
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(NOT _git_result EQUAL 0)
        message(FATAL_ERROR "Dependency is not a Git checkout: ${source}")
    endif()
    if(AIRECE_ENFORCE_DEPENDENCY_PINS AND NOT _revision STREQUAL expected)
        message(FATAL_ERROR
            "Dependency pin mismatch for ${source}: expected ${expected}, found ${_revision}")
    endif()
    execute_process(
        # A checkout shared by Windows and WSL can appear dirty solely because
        # NTFS does not preserve Unix modes and a checkout shared with Windows
        # may contain CRLF worktree files. Content changes still fail the
        # release build; only platform representation noise is ignored here.
        COMMAND git -c core.filemode=false -c core.autocrlf=true
            -C "${source}" status --porcelain
        RESULT_VARIABLE _status_result
        OUTPUT_VARIABLE _dirty
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(NOT _status_result EQUAL 0)
        message(FATAL_ERROR "Could not inspect dependency cleanliness: ${source}")
    endif()
    if(NOT _dirty STREQUAL "")
        if(NOT AIRECE_ALLOW_DIRTY_DEPENDENCIES)
            message(FATAL_ERROR
                "Dependency has uncommitted changes: ${source}. "
                "Commit the dependency or explicitly configure a non-release development "
                "build with -DAIRECE_ALLOW_DIRTY_DEPENDENCIES=ON.")
        endif()
        string(APPEND _revision "-dirty")
    endif()
    set(${output} "${_revision}" PARENT_SCOPE)
endfunction()

airece_git_revision("${AIRECE_XAIR_SOURCE_DIR}" "${AIRECE_XAIR_PIN}"
    AIRECE_XAIR_REVISION)
airece_git_revision("${AIRECE_XAIR_CFG_SOURCE_DIR}" "${AIRECE_XAIR_CFG_PIN}"
    AIRECE_XAIR_CFG_REVISION)
airece_git_revision("${AIRECE_XAIR_SYM_SOURCE_DIR}" "${AIRECE_XAIR_SYM_PIN}"
    AIRECE_XAIR_SYM_REVISION)
airece_git_revision("${AIRECE_Z3_SOURCE_DIR}" "${AIRECE_Z3_PIN}"
    AIRECE_Z3_REVISION)

set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
add_subdirectory("${AIRECE_ZYDIS_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/vendor/zydis")

set(XAIR_BUILD_ALL OFF CACHE BOOL "" FORCE)
set(XAIR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(XAIR_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(XAIR_BUILD_FUZZERS OFF CACHE BOOL "" FORCE)
set(XAIR_USE_ZYDIS ON CACHE BOOL "" FORCE)
set(XAIR_ENABLE_BOOTSTRAP_DECODER OFF CACHE BOOL "" FORCE)
set(XAIR_ZYDIS_ROOT "${AIRECE_ZYDIS_SOURCE_DIR}" CACHE PATH "" FORCE)
set(XAIR_CFG_ENABLE_LEGACY_DECODERS OFF CACHE BOOL "" FORCE)
set(XAIR_Z3_SOURCE_ROOT "${AIRECE_Z3_SOURCE_DIR}" CACHE PATH "" FORCE)
add_subdirectory("${AIRECE_XAIR_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/vendor/xair")
add_subdirectory("${AIRECE_XAIR_CFG_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/vendor/xair_cfg")
add_subdirectory("${AIRECE_XAIR_SYM_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/vendor/xair_sym")

get_target_property(_airece_xair_sources xair SOURCES)
get_target_property(_airece_cfg_sources xair_cfg SOURCES)
string(JOIN ";" _airece_xair_source_list ${_airece_xair_sources})
string(JOIN ";" _airece_cfg_source_list ${_airece_cfg_sources})
if(_airece_xair_source_list MATCHES "xair_x86_decode\\.c")
    message(FATAL_ERROR "AIRECE production build unexpectedly contains the bootstrap decoder")
endif()
if(_airece_cfg_source_list MATCHES "xair_cfg_decode(_zydis_mini)?\\.c")
    message(FATAL_ERROR "AIRECE production build unexpectedly contains a legacy CFG decoder")
endif()

configure_file(
    cmake/airece_build_config.hpp.in
    "${CMAKE_CURRENT_BINARY_DIR}/generated/airece_build_config.hpp"
    @ONLY)

add_library(airece_core STATIC
    src/emit/agent_json.cpp
    src/emit/semantic_json.cpp
    src/emit/semantic_text.cpp
    src/semantic/api_model.cpp
    src/semantic/compact_view.cpp
    src/semantic/control_view.cpp
    src/semantic/directed_flow.cpp
    src/semantic/enrichment.cpp
    src/semantic/expression_view.cpp
    src/semantic/variable_view.cpp
    src/session/analysis_session.cpp
    src/session/decode_cache.cpp
    src/version.cpp)
add_library(AIRECE::core ALIAS airece_core)
target_compile_features(airece_core PUBLIC cxx_std_20)
target_include_directories(airece_core
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(airece_core PRIVATE
    AIRECE_BUILD_CONFIG="$<CONFIG>")
target_link_libraries(airece_core PUBLIC xair_sym)

add_executable(airece src/cli/main.cpp)
target_compile_features(airece PRIVATE cxx_std_20)
target_link_libraries(airece PRIVATE airece_core)

if(MSVC)
    target_compile_options(airece_core PRIVATE /W4 /WX /permissive-)
    target_compile_options(airece PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(airece_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(airece PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

set(AIRECE_NOTICE_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/THIRD_PARTY_NOTICES.md")
add_custom_command(
    OUTPUT "${AIRECE_NOTICE_OUTPUT}"
    COMMAND "${CMAKE_COMMAND}"
        -DAIRECE_NOTICE_OUTPUT=${AIRECE_NOTICE_OUTPUT}
        -DAIRECE_NOTICE_XAIR=${AIRECE_XAIR_SOURCE_DIR}/LICENSE
        -DAIRECE_NOTICE_XAIR_CFG=${AIRECE_XAIR_CFG_SOURCE_DIR}/LICENSE
        -DAIRECE_NOTICE_XAIR_SYM=${AIRECE_XAIR_SYM_SOURCE_DIR}/LICENSE
        -DAIRECE_NOTICE_ZYDIS=${AIRECE_ZYDIS_SOURCE_DIR}/LICENSE
        -DAIRECE_NOTICE_ZYCORE=${AIRECE_ZYDIS_SOURCE_DIR}/dependencies/zycore/LICENSE
        -DAIRECE_NOTICE_Z3=${AIRECE_Z3_SOURCE_DIR}/LICENSE.txt
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GenerateThirdPartyNotices.cmake"
    DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GenerateThirdPartyNotices.cmake"
        "${AIRECE_XAIR_SOURCE_DIR}/LICENSE"
        "${AIRECE_XAIR_CFG_SOURCE_DIR}/LICENSE"
        "${AIRECE_XAIR_SYM_SOURCE_DIR}/LICENSE"
        "${AIRECE_ZYDIS_SOURCE_DIR}/LICENSE"
        "${AIRECE_ZYDIS_SOURCE_DIR}/dependencies/zycore/LICENSE"
        "${AIRECE_Z3_SOURCE_DIR}/LICENSE.txt"
    VERBATIM)
add_custom_target(airece_notices ALL DEPENDS "${AIRECE_NOTICE_OUTPUT}")

if(BUILD_TESTING)
    function(airece_add_semantic_fixture target output_name optimized)
        add_library(${target} SHARED tests/fixtures/semantic_contract.c)
        set_target_properties(${target} PROPERTIES OUTPUT_NAME ${output_name})
        if(MSVC)
            if(optimized)
                target_compile_options(${target} PRIVATE /O2 /Ob2 /GS-)
            else()
                target_compile_options(${target} PRIVATE /Od /Ob0 /GS-)
            endif()
            if(POLICY CMP0184)
                set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_CHECKS "")
            elseif(NOT optimized)
                target_compile_definitions(${target} PRIVATE AIRECE_RTC_STUBS=1)
            endif()
            target_link_options(${target} PRIVATE
                /ENTRY:airece_semantic_entry /NODEFAULTLIB)
        elseif(optimized)
            target_compile_options(${target} PRIVATE -O2 -fno-semantic-interposition)
        else()
            target_compile_options(${target} PRIVATE -O0 -fno-semantic-interposition)
        endif()
    endfunction()
    airece_add_semantic_fixture(
        airece_semantic_source_fixture airece-semantic-source-fixture FALSE)
    airece_add_semantic_fixture(
        airece_semantic_source_fixture_opt airece-semantic-source-fixture-opt TRUE)

    add_executable(airece_decoder_boundary_tests
        tests/semantic/decoder_boundary_test.cpp)
    target_compile_features(airece_decoder_boundary_tests PRIVATE cxx_std_20)
    target_link_libraries(airece_decoder_boundary_tests PRIVATE airece_core)
    add_test(NAME airece_decoder_boundary COMMAND airece_decoder_boundary_tests)

    add_executable(airece_expression_view_tests
        tests/semantic/expression_view_test.cpp)
    target_compile_features(airece_expression_view_tests PRIVATE cxx_std_20)
    target_link_libraries(airece_expression_view_tests PRIVATE airece_core)
    add_test(NAME airece_expression_view
        COMMAND airece_expression_view_tests
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/golden/expression-basic.txt")

    add_executable(airece_variable_view_tests
        tests/semantic/variable_view_test.cpp)
    target_compile_features(airece_variable_view_tests PRIVATE cxx_std_20)
    target_link_libraries(airece_variable_view_tests PRIVATE airece_core)
    add_test(NAME airece_variable_view COMMAND airece_variable_view_tests)

    add_executable(airece_control_view_tests
        tests/semantic/control_view_test.cpp)
    target_compile_features(airece_control_view_tests PRIVATE cxx_std_20)
    target_link_libraries(airece_control_view_tests PRIVATE airece_core)
    add_test(NAME airece_control_view COMMAND airece_control_view_tests)

    add_executable(airece_api_model_tests tests/semantic/api_model_test.cpp)
    target_compile_features(airece_api_model_tests PRIVATE cxx_std_20)
    target_link_libraries(airece_api_model_tests PRIVATE airece_core)
    add_test(NAME airece_api_model COMMAND airece_api_model_tests)

    add_executable(airece_directed_flow_tests
        tests/semantic/directed_flow_test.cpp)
    target_compile_features(airece_directed_flow_tests PRIVATE cxx_std_20)
    target_link_libraries(airece_directed_flow_tests PRIVATE airece_core)
    add_test(NAME airece_directed_flow COMMAND airece_directed_flow_tests)

    add_executable(airece_decode_cache_tests tests/session/decode_cache_test.cpp)
    target_compile_features(airece_decode_cache_tests PRIVATE cxx_std_20)
    target_link_libraries(airece_decode_cache_tests PRIVATE airece_core)
    add_test(NAME airece_decode_cache COMMAND airece_decode_cache_tests)

    add_executable(airece_analysis_session_tests
        tests/session/analysis_session_test.cpp)
    target_compile_features(airece_analysis_session_tests PRIVATE cxx_std_20)
    target_link_libraries(airece_analysis_session_tests PRIVATE airece_core)
    add_test(NAME airece_analysis_session
        COMMAND airece_analysis_session_tests
            "${AIRECE_XAIR_SOURCE_DIR}/tests/corpus/phase3/control-flow.pe64"
            "$<TARGET_FILE:airece>")

    add_executable(airece_xair_sym_lazy_tests
        "${AIRECE_XAIR_SYM_SOURCE_DIR}/tests/test_lazy_context.c")
    target_link_libraries(airece_xair_sym_lazy_tests PRIVATE xair_sym)
    add_test(NAME airece_xair_sym_lazy COMMAND airece_xair_sym_lazy_tests)

    add_executable(airece_version_tests tests/cli/version_test.cpp)
    target_compile_features(airece_version_tests PRIVATE cxx_std_20)
    target_link_libraries(airece_version_tests PRIVATE airece_core)
    add_test(NAME airece_version_unit COMMAND airece_version_tests)
    add_test(NAME airece_version_cli COMMAND airece --version)
    set_tests_properties(airece_version_cli PROPERTIES
        PASS_REGULAR_EXPRESSION "decoder zydis \\(sole production path\\)")

    foreach(_command IN ITEMS inspect functions)
        add_test(NAME airece_${_command}_cli
            COMMAND "${CMAKE_COMMAND}"
                -DAIRECE_EXE=$<TARGET_FILE:airece>
                -DFIXTURE=${AIRECE_XAIR_SOURCE_DIR}/tests/corpus/phase3/control-flow.pe64
                -DCOMMAND_NAME=${_command}
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/analysis_command_test.cmake")
    endforeach()

    add_test(NAME airece_expr_cli
        COMMAND "${CMAKE_COMMAND}"
            -DAIRECE_EXE=$<TARGET_FILE:airece>
            -DFIXTURE=${AIRECE_XAIR_SOURCE_DIR}/tests/corpus/phase3/control-flow.pe64
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/expression_command_test.cmake")

    add_test(NAME airece_vars_cli
        COMMAND "${CMAKE_COMMAND}"
            -DAIRECE_EXE=$<TARGET_FILE:airece>
            -DFIXTURE=${AIRECE_XAIR_SOURCE_DIR}/tests/corpus/phase3/control-flow.pe64
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/variable_command_test.cmake")

    add_test(NAME airece_fn_cli
        COMMAND "${CMAKE_COMMAND}"
            -DAIRECE_EXE=$<TARGET_FILE:airece>
            -DFIXTURE=${AIRECE_XAIR_SOURCE_DIR}/tests/corpus/phase3/control-flow.pe64
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/function_command_test.cmake")

    add_test(NAME airece_protocol_cli
        COMMAND "${CMAKE_COMMAND}"
            -DAIRECE_EXE=$<TARGET_FILE:airece>
            -DFIXTURE=${AIRECE_XAIR_SOURCE_DIR}/tests/corpus/phase3/control-flow.pe64
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/protocol_command_test.cmake")

    add_test(NAME airece_flow_cli
        COMMAND "${CMAKE_COMMAND}"
            -DAIRECE_EXE=$<TARGET_FILE:airece>
            -DFIXTURE=${AIRECE_XAIR_SOURCE_DIR}/tests/corpus/phase3/control-flow.pe64
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/flow_command_test.cmake")

    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    find_program(AIRECE_CLANG_CL_EXECUTABLE clang-cl)
    find_program(AIRECE_LLD_LINK_EXECUTABLE lld-link)
    set(AIRECE_CLANG_FIXTURE_ARGUMENTS)
    if(AIRECE_CLANG_CL_EXECUTABLE AND AIRECE_LLD_LINK_EXECUTABLE)
        list(APPEND AIRECE_CLANG_FIXTURE_ARGUMENTS
            --source "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/semantic_contract.c"
            --clang-cl "${AIRECE_CLANG_CL_EXECUTABLE}"
            --lld-link "${AIRECE_LLD_LINK_EXECUTABLE}")
    endif()
    add_test(NAME airece_source_semantics
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/source_semantics_test.py"
            $<TARGET_FILE:airece>
            $<TARGET_FILE:airece_semantic_source_fixture>
            $<TARGET_FILE:airece_semantic_source_fixture_opt>
            ${AIRECE_CLANG_FIXTURE_ARGUMENTS})

    if(WIN32 AND AIRECE_CLANG_CL_EXECUTABLE AND AIRECE_LLD_LINK_EXECUTABLE)
        add_test(NAME airece_platform_matrix
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/platform_matrix_test.py"
                --airece $<TARGET_FILE:airece>
                --source "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/platform_abi.c"
                --format pe
                --clang-cl "${AIRECE_CLANG_CL_EXECUTABLE}"
                --lld-link "${AIRECE_LLD_LINK_EXECUTABLE}")
    elseif(UNIX)
        add_test(NAME airece_platform_matrix
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/platform_matrix_test.py"
                --airece $<TARGET_FILE:airece>
                --source "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/platform_abi.c"
                --format elf
                --cc "${CMAKE_C_COMPILER}")
    endif()

    add_test(NAME airece_evaluation_smoke
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/evaluate.py"
            --airece $<TARGET_FILE:airece>
            --binary "${AIRECE_XAIR_SOURCE_DIR}/tests/corpus/phase3/control-flow.pe64"
            --max-samples 1
            --timeout-seconds 30
            --wall-time-ms 5000)

    add_test(NAME airece_notices_complete
        COMMAND "${CMAKE_COMMAND}"
            -DNOTICE=${AIRECE_NOTICE_OUTPUT}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/notices_test.cmake")
endif()

install(TARGETS airece airece_core
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(FILES "${AIRECE_NOTICE_OUTPUT}" LICENSE
    DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/airece")

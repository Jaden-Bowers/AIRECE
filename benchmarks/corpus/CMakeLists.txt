cmake_minimum_required(VERSION 3.24)
project(airece_benchmark_corpus LANGUAGES C CXX)

set(BENCH_OPT "O2" CACHE STRING "O0 or O2")
if(NOT BENCH_OPT MATCHES "^(O0|O2)$")
  message(FATAL_ERROR "BENCH_OPT must be O0 or O2")
endif()

function(configure_fixture target)
  target_compile_options(${target} PRIVATE /nologo /GS- /Gy- /Zl
    $<$<STREQUAL:${BENCH_OPT},O0>:/Od>
    $<$<STREQUAL:${BENCH_OPT},O2>:/O2>)
  target_link_options(${target} PRIVATE /NOLOGO /NODEFAULTLIB /DEBUG:NONE
    /INCREMENTAL:NO /OPT:NOREF /OPT:NOICF /ENTRY:bench_entry)
  set_target_properties(${target} PROPERTIES PREFIX "" SUFFIX ".dll")
endfunction()

add_library(artifact_c SHARED source/fixture_c.c)
target_link_libraries(artifact_c PRIVATE kernel32)
configure_fixture(artifact_c)

add_library(artifact_cpp SHARED source/fixture_cpp.cpp)
target_compile_options(artifact_cpp PRIVATE /GR- /EHsc-)
configure_fixture(artifact_cpp)

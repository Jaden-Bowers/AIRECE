cmake_minimum_required(VERSION 3.24)
project(airece_benchmark_corpus LANGUAGES C CXX)

set(BENCH_OPT "O2" CACHE STRING "O0 or O2")
set(BENCH_CRT "none" CACHE STRING "none, static, or dynamic")
if(NOT BENCH_OPT MATCHES "^(O0|O2)$")
  message(FATAL_ERROR "BENCH_OPT must be O0 or O2")
endif()
if(NOT BENCH_CRT MATCHES "^(none|static|dynamic)$")
  message(FATAL_ERROR "BENCH_CRT must be none, static, or dynamic")
endif()

function(configure_fixture target)
  target_compile_options(${target} PRIVATE /nologo /GS- /Gy-
    $<$<STREQUAL:${BENCH_OPT},O0>:/Od>
    $<$<STREQUAL:${BENCH_OPT},O2>:/O2>)
  target_link_options(${target} PRIVATE /NOLOGO /DEBUG:NONE /INCREMENTAL:NO
    /OPT:NOREF /OPT:NOICF)
  if(BENCH_CRT STREQUAL "none")
    target_compile_options(${target} PRIVATE /Zl)
    target_link_options(${target} PRIVATE /NODEFAULTLIB /ENTRY:bench_entry)
  elseif(BENCH_CRT STREQUAL "static")
    set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
  else()
    set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
  endif()
  set_target_properties(${target} PROPERTIES PREFIX "" SUFFIX ".dll")
endfunction()

add_library(artifact_c SHARED source/fixture_c.c)
target_link_libraries(artifact_c PRIVATE kernel32)
configure_fixture(artifact_c)

add_library(artifact_cpp SHARED source/fixture_cpp.cpp)
target_compile_options(artifact_cpp PRIVATE /GR- /EHsc-)
configure_fixture(artifact_cpp)

find_package(Threads REQUIRED)

include_directories(acutest/)

if(FLB_IN_LIB)
  if(FLB_OUT_LIB)
    list(APPEND check_PROGRAMS
      flb_test_engine.c
      )
  endif()

  if(FLB_OUT_COUNTER)
    list(APPEND check_PROGRAMS
      flb_test_counter.c
      )
  endif()

  if(FLB_OUT_ES)
    list(APPEND check_PROGRAMS
      flb_test_elasticsearch.c
      )
  endif()

  if(FLB_OUT_EXIT)
    list(APPEND check_PROGRAMS
      flb_test_exit.c
      )
  endif()

  if(FLB_OUT_FILE)
    list(APPEND check_PROGRAMS
      flb_test_file.c
      )
  endif()

  if(FLB_OUT_FLOWCOUNTER)
    list(APPEND check_PROGRAMS
      flb_test_flowcounter.c
      )
  endif()

  if(FLB_OUT_FORWARD)
    list(APPEND check_PROGRAMS
      flb_test_forward.c
      )
  endif()

  if(FLB_OUT_NULL)
    list(APPEND check_PROGRAMS
      flb_test_null.c
      )
  endif()

  if(FLB_OUT_PLOT)
    list(APPEND check_PROGRAMS
      flb_test_plot.c
      )
  endif()

  if(FLB_OUT_RETRY)
    list(APPEND check_PROGRAMS
      flb_test_retry.c
      )
  endif()

  if(FLB_OUT_STDOUT)
    list(APPEND check_PROGRAMS
      flb_test_stdout.c
      )
  endif()

  if(FLB_OUT_TD)
    list(APPEND check_PROGRAMS
      flb_test_td.c
      )
  endif()
endif()

if(FLB_OUT_LIB)
  if(FLB_IN_CPU)
    list(APPEND check_PROGRAMS
      flb_test_in_cpu.c
      )
  endif()

  if(FLB_IN_DUMMY)
    list(APPEND check_PROGRAMS
      flb_test_in_dummy.c
      )
  endif()

  if(FLB_IN_HEAD)
    list(APPEND check_PROGRAMS
      flb_test_in_head.c
      )
  endif()

  if(FLB_IN_MEM)
    list(APPEND check_PROGRAMS
      flb_test_in_mem.c
      )
  endif()

  if(FLB_IN_PROC)
    list(APPEND check_PROGRAMS
      flb_test_in_proc.c
      )
  endif()

  if(FLB_IN_RANDOM)
    list(APPEND check_PROGRAMS
      flb_test_in_random.c
      )
  endif()
endif()

if(FLB_IN_LIB AND FLB_OUT_LIB)
  if(FLB_FILTER_STDOUT)
    list(APPEND check_PROGRAMS
      flb_test_filter_stdout.c
      )
  endif()

  if(FLB_FILTER_GREP)
    list(APPEND check_PROGRAMS
      flb_test_filter_grep.c
      )
  endif()
endif()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/flb_tests_runtime.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/flb_tests_runtime.h"
  )

foreach(source_file ${check_PROGRAMS})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  add_executable(
    ${source_file_we}
    ${source_file}
    )
  target_link_libraries(${source_file_we}
    fluent-bit-static
    ${CMAKE_THREAD_LIBS_INIT}
    )
  add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR
      "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set_property(TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -g -O3")
  endif()
endforeach()

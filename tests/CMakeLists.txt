find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

include_directories (
  ${GTEST_INCLUDE_DIRS}
  )

if(FLB_IN_LIB)
  if(FLB_OUT_LIB)
     list(APPEND check_PROGRAMS
       flb_test_engine.cpp
       )
  endif()

  if(FLB_OUT_TD)
     list(APPEND check_PROGRAMS
       flb_test_td.cpp
       )
  endif()

  if(FLB_OUT_STDOUT)
     list(APPEND check_PROGRAMS
       flb_test_stdout.cpp
       )
  endif()

  if(FLB_OUT_FORWARD)
     list(APPEND check_PROGRAMS
       flb_test_fluentd.cpp
       )
  endif()

  if(FLB_OUT_ES)
     list(APPEND check_PROGRAMS
       flb_test_elasticsearch.cpp
       )
  endif()

  if(FLB_OUT_FILE)
     list(APPEND check_PROGRAMS
       flb_test_file.cpp
       )
  endif()

  if(FLB_OUT_COUNTER)
     list(APPEND check_PROGRAMS
       flb_test_counter.cpp
       )
  endif()

  if(FLB_OUT_FLOWCOUNTER)
	 list(APPEND check_PROGRAMS
	   flb_test_flowcounter.cpp
	   )
  endif()

  if(FLB_OUT_EXIT)
     list(APPEND check_PROGRAMS
	   flb_test_exit.cpp
	   )
  endif()

  if(FLB_OUT_NULL)
     list(APPEND check_PROGRAMS
	   flb_test_null.cpp
	   )
  endif()

  if(FLB_OUT_PLOT)
     list(APPEND check_PROGRAMS
	   flb_test_plot.cpp
	   )
  endif()

  if(FLB_OUT_RETRY)
     list(APPEND check_PROGRAMS
	   flb_test_retry.cpp
	   )
  endif()
endif()

if(FLB_OUT_LIB)
  if(FLB_IN_CPU)
    list(APPEND check_PROGRAMS
      flb_test_in_cpu.cpp
      )
  endif()

  if(FLB_IN_PROC)
    list(APPEND check_PROGRAMS
      flb_test_in_proc.cpp
      )
  endif()

  if(FLB_IN_HEAD)
    list(APPEND check_PROGRAMS
      flb_test_in_head.cpp
      )
  endif()

  if(FLB_IN_MEM)
    list(APPEND check_PROGRAMS
      flb_test_in_mem.cpp
      )
  endif()

  if(FLB_IN_RANDOM)
    list(APPEND check_PROGRAMS
      flb_test_in_random.cpp
      )
  endif()
endif()

if(FLB_IN_LIB AND FLB_OUT_LIB)
  if(FLB_FILTER_STDOUT)
    list(APPEND check_PROGRAMS
      flb_test_filter_stdout.cpp
      )
  endif()

  if(FLB_FILTER_GREP)
    list(APPEND check_PROGRAMS
      flb_test_filter_grep.cpp
      )
  endif()
endif()

foreach(source_file ${check_PROGRAMS})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  add_executable(
    ${source_file_we}
    ${source_file}
    )
  target_link_libraries(${source_file_we}
    fluent-bit-static
    ${GTEST_BOTH_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    )
  add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR
      "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set_property(TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -g -O3")
  endif()
endforeach()

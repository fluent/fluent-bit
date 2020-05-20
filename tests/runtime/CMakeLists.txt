find_package(Threads REQUIRED)

include_directories(acutest/)

define_property(GLOBAL PROPERTY CHECK_PROGRAMS
  BRIEF_DOCS "Runtime Test Programs"
  FULL_DOCS "Runtime Test Programs")
set_property(GLOBAL PROPERTY CHECK_PROGRAMS "")

# Macro to set definitions
macro(FLB_RT_TEST BUILT src)
  if (${BUILT})
    list(APPEND CHECK_PROGRAMS
      ${src}
      )
  endif()
endmacro()

# Input Plugins
if(FLB_OUT_LIB)
  # These plugins works only on Linux
  if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    FLB_RT_TEST(FLB_IN_CPU           "in_cpu.c")
    FLB_RT_TEST(FLB_IN_DISK          "in_disk.c")
    FLB_RT_TEST(FLB_IN_MEM           "in_mem.c")
    FLB_RT_TEST(FLB_IN_PROC          "in_proc.c")
  endif()
  FLB_RT_TEST(FLB_IN_HEAD          "in_head.c")
  FLB_RT_TEST(FLB_IN_DUMMY         "in_dummy.c")
  FLB_RT_TEST(FLB_IN_RANDOM        "in_random.c")
  FLB_RT_TEST(FLB_IN_TAIL          "in_tail.c")
endif()

# Filter Plugins
if(FLB_IN_LIB AND FLB_OUT_LIB)
  FLB_RT_TEST(FLB_FILTER_STDOUT     "filter_stdout.c")
  FLB_RT_TEST(FLB_FILTER_GREP       "filter_grep.c")
  FLB_RT_TEST(FLB_FILTER_THROTTLE   "filter_throttle.c")
  FLB_RT_TEST(FLB_FILTER_NEST       "filter_nest.c")
  FLB_RT_TEST(FLB_FILTER_KUBERNETES "filter_kubernetes.c")
  FLB_RT_TEST(FLB_FILTER_PARSER     "filter_parser.c")
  FLB_RT_TEST(FLB_FILTER_MODIFY     "filter_modify.c")
endif()


# Output Plugins
if(FLB_IN_LIB)
  FLB_RT_TEST(FLB_OUT_LIB          "core_engine.c")
  FLB_RT_TEST(FLB_OUT_COUNTER      "out_counter.c")
  FLB_RT_TEST(FLB_OUT_ES           "out_elasticsearch.c")
  FLB_RT_TEST(FLB_OUT_EXIT         "out_exit.c")
  FLB_RT_TEST(FLB_OUT_FILE         "out_file.c")
  FLB_RT_TEST(FLB_OUT_FLOWCOUNTER  "out_flowcounter.c")
  FLB_RT_TEST(FLB_OUT_FORWARD      "out_forward.c")
  FLB_RT_TEST(FLB_OUT_NULL         "out_null.c")
  FLB_RT_TEST(FLB_OUT_PLOT         "out_plot.c")
  FLB_RT_TEST(FLB_OUT_RETRY        "out_retry.c")
  FLB_RT_TEST(FLB_OUT_STDOUT       "out_stdout.c")
  FLB_RT_TEST(FLB_OUT_TD           "out_td.c")
endif()


# HTTP Client Debug (requires -DFLB_HTTP_CLIENT_DEBUG=On)
if(FLB_HTTP_CLIENT_DEBUG)
  FLB_RT_TEST(FLB_OUT_TD           "http_callbacks.c")
endif()

set(SYSTEMD_LIB, "")
if(FLB_HAVE_SYSTEMD)
    set(SYSTEMD_LIB, "systemd")
endif()

set(FLB_TESTS_DATA_PATH ${CMAKE_CURRENT_SOURCE_DIR})
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/flb_tests_runtime.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/flb_tests_runtime.h"
  )

foreach(source_file ${CHECK_PROGRAMS})
  get_filename_component(o_source_file_we ${source_file} NAME_WE)
  set(source_file_we flb-rt-${o_source_file_we})
  if(FLB_WITHOUT_${source_file_we})
    message("Skipping test ${source_file_we}")
  else()
    add_executable(
      ${source_file_we}
      ${source_file}
      )
    add_sanitizers(${source_file_we})
    target_link_libraries(${source_file_we}
      fluent-bit-static
      ${CMAKE_THREAD_LIBS_INIT}
      ${SYSTEMD_LIB}
      )
    add_test(NAME ${source_file_we}
            COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we}
            WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/build)
    set_tests_properties(${source_file_we} PROPERTIES LABELS "runtime")
    set_property(TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-D${o_source_file_we}")
  endif()
endforeach()

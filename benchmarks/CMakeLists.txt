find_package(Threads REQUIRED)

set(FLB_BENCHMARKS_DATA_PATH ${CMAKE_CURRENT_SOURCE_DIR})
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/bench_config.h.in
  ${CMAKE_CURRENT_SOURCE_DIR}/bench_config.h
  )
configure_file(sample.json ${CMAKE_CURRENT_BINARY_DIR}/sample.json COPYONLY)

include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/tests/lib/acutest
  ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(flb-bench-pack pack_bench.c)
add_sanitizers(flb-bench-pack)
target_link_libraries(flb-bench-pack fluent-bit-static cfl-static ${CMAKE_THREAD_LIBS_INIT})

add_test(NAME flb-bench-pack
  COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/flb-bench-pack
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(flb-bench-pack PROPERTIES LABELS "benchmarks")

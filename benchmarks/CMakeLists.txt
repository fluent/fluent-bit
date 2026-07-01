add_executable(flb-bench-pack_json pack_json.c)
target_link_libraries(flb-bench-pack_json
  fluent-bit-static
  ${CMAKE_THREAD_LIBS_INIT}
)

add_executable(flb-bench-processor_sampling
  flb-bench-processor_sampling.c
  ../plugins/processor_sampling/sampling_probabilistic.c
  ../plugins/processor_sampling/sampling_span_registry.c
  ../plugins/processor_sampling/sampling_tail.c
)
target_compile_definitions(flb-bench-processor_sampling
  PRIVATE FLB_SAMPLING_BENCH=1
)
target_link_libraries(flb-bench-processor_sampling
  fluent-bit-static
  ${CMAKE_THREAD_LIBS_INIT}
)

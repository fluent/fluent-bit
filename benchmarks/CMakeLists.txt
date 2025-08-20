add_executable(flb-bench-pack_json pack_json.c)
target_link_libraries(flb-bench-pack_json
  fluent-bit-static
  ${CMAKE_THREAD_LIBS_INIT}
)


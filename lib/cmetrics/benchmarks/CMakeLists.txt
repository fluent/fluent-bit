add_executable(cmt-benchmark benchmark.c)
target_link_libraries(cmt-benchmark cmetrics-static cfl-static fluent-otel-proto)

if(NOT CMT_SYSTEM_WINDOWS)
  target_link_libraries(cmt-benchmark pthread)
endif()

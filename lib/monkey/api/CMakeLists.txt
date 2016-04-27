set(src
  test.c)

add_executable(api_test ${src})
target_link_libraries(api_test monkey-core-static)

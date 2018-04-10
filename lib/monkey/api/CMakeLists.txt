set(src
  test.c)

add_executable(api_test ${src})
target_link_libraries(api_test monkey-core-static)

set(src
  errors.c
  )

add_executable(api_error ${src})
target_link_libraries(api_error monkey-core-static)

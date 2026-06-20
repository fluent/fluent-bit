set(src
  test.c)

add_executable(api_test ${src})

set(src
  errors.c
  )

add_executable(api_error ${src})

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
  target_link_libraries(api_test monkey-core-static mk_core ws2_32)
  target_link_libraries(api_error monkey-core-static mk_core ws2_32)
else()
  target_link_libraries(api_test monkey-core-static)
  target_link_libraries(api_error monkey-core-static)
endif()

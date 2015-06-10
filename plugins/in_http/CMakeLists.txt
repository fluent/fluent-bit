set(src
  in_http.c)

FLB_PLUGIN(in_http "${src}" "")
target_link_libraries(flb-plugin-in_http ${CMAKE_BINARY_DIR}/library/libmonkey.a)

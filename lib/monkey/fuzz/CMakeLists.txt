set(src
  mk_fuzz_me.c)

add_executable(mk_fuzz_me ${src})
target_link_libraries(mk_fuzz_me monkey-core-static)

set(src
  mk_check.c)

add_executable(mk_check ${src})
target_link_libraries(mk_check monkey-core-static)

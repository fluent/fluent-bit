set(src
  in_kmsg.c
  flb_network.c
  fluent-bit.c
  )

include_directories(../lib/)
add_executable(fluent-bit ${src})
target_link_libraries(fluent-bit msgpack mk_config)

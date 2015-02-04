set(src
  in_kmsg.c
  flb_network.c
  flb_utils.c
  fluent-bit.c
  )

include_directories(../lib/ ../lib/msgpack-0.5.9/src)
add_executable(fluent-bit ${src})
target_link_libraries(fluent-bit msgpack mk_config)

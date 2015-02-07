set(src
  in_cpu.c
  in_kmsg.c
  flb_input.c
  flb_output.c
  flb_network.c
  flb_utils.c
  fluent-bit.c
  )

include_directories(../lib/ ../lib/msgpack-0.5.9/src)
add_executable(fluent-bit ${src})
target_link_libraries(fluent-bit msgpack mk_config)

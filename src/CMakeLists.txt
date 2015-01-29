set(src
  in_kmsg.c
  flb_network.c
  fluent-bit.c
  )

include_directories(../lib/)
add_executable(fluent-bit ${src})

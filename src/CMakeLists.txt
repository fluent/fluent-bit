if (DEFINED FLB_XBEE)
  set(src ${src} in_xbee.c)
  set(extra_headers ../lib/libxbee-v3)
  set(extra_libs pthread rt)
endif (DEFINED FLB_XBEE)

set(src
  ${src}
  in_cpu.c
  in_kmsg.c
  flb_input.c
  flb_output.c
  flb_config.c
  flb_network.c
  flb_utils.c
  flb_engine.c
  fluent-bit.c
  )


include_directories(../lib/ ../lib/msgpack-0.5.9/src ${extra_headers})
add_executable(fluent-bit ${src})
target_link_libraries(fluent-bit msgpack mk_config)

if (DEFINED FLB_XBEE)
  set_target_properties(fluent-bit PROPERTIES
    COMPILE_FLAGS -DFLB_XBEE_ENABLED)
  target_link_libraries(fluent-bit xbee ${extra_libs})
endif (DEFINED FLB_XBEE)

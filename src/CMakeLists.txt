IF(WITH_XBEE)
  SET(src ${src} in_xbee.c)
  SET(extra_headers ../lib/libxbee-v3)
  SET(extra_libs pthread rt)
ENDIF()

SET(src
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

INCLUDE_DIRECTORIES(../lib/ ../lib/msgpack-0.5.9/src ${extra_headers})
ADD_EXECUTABLE(fluent-bit ${src})
TARGET_LINK_LIBRARIES(fluent-bit msgpack mk_config)

IF(WITH_XBEE)
  SET_TARGET_PROPERTIES(fluent-bit PROPERTIES
    COMPILE_FLAGS -DFLB_XBEE_ENABLED)
  TARGET_LINK_LIBRARIES(fluent-bit xbee ${extra_libs})
ENDIF ()

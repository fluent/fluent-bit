IF(WITH_XBEE)
  SET(src ${src} in_xbee.c)
  SET(extra_headers ../lib/libxbee-v3)
  SET(extra_libs pthread rt)
ENDIF()

SET(src
  ${src}
  in_cpu.c
  in_kmsg.c
  flb_pack.c
  flb_input.c
  flb_output.c
  flb_config.c
  flb_network.c
  flb_utils.c
  flb_engine.c
  )

INCLUDE_DIRECTORIES(
  ../lib/
  ../lib/jsmn
  ../lib/msgpack-0.5.9/src
  ${extra_headers}
  )

# Shared Library
ADD_LIBRARY(fluent-bit-shared SHARED ${src})
SET_TARGET_PROPERTIES(fluent-bit-shared
  PROPERTIES OUTPUT_NAME fluent-bit)

# Static Library
ADD_LIBRARY(fluent-bit-static STATIC ${src})
SET_TARGET_PROPERTIES(fluent-bit-static PROPERTIES
  OUTPUT_NAME fluent-bit)
SET_TARGET_PROPERTIES(fluent-bit-static PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${FLB_ROOT}/library")

IF(WITH_XBEE)
  SET_TARGET_PROPERTIES(fluent-bit-shared PROPERTIES
    COMPILE_FLAGS -DFLB_HAVE_XBEE)
  TARGET_LINK_LIBRARIES(fluent-bit-shared xbee ${extra_libs})

  SET_TARGET_PROPERTIES(fluent-bit-static PROPERTIES
    COMPILE_FLAGS -DFLB_HAVE_XBEE)
  TARGET_LINK_LIBRARIES(fluent-bit-static xbee ${extra_libs})
ENDIF()

# Link dependencies to Fluent-Bit library core
TARGET_LINK_LIBRARIES(fluent-bit-shared msgpack mk_config jsmn)
TARGET_LINK_LIBRARIES(fluent-bit-static msgpack mk_config jsmn)

# Executable
IF(NOT WITHOUT_BIN)
  ADD_EXECUTABLE(fluent-bit-bin fluent-bit.c)
  TARGET_LINK_LIBRARIES(fluent-bit-bin fluent-bit-static)
  SET_TARGET_PROPERTIES(fluent-bit-bin
    PROPERTIES OUTPUT_NAME fluent-bit)
ENDIF()

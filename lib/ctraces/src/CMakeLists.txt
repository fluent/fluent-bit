set(src
  ctraces.c
  ctr_resource.c
  ctr_span.c
  ctr_link.c
  ctr_scope.c
  ctr_log.c
  ctr_id.c
  ctr_random.c
  ctr_utils.c
  ctr_attributes.c
  ctr_version.c
  ctr_mpack_utils.c
  # encoders
  ctr_encode_text.c
  ctr_encode_msgpack.c
  ctr_encode_opentelemetry.c
  # decoders
  ctr_decode_msgpack.c
  ctr_decode_opentelemetry.c
  )

# Static Library
add_library(ctraces-static STATIC ${src})
target_link_libraries(ctraces-static mpack-static cfl-static fluent-otel-proto)

# Install Library
if(MSVC)
  # Rename the output for Windows environment to avoid naming issues
  set_target_properties(ctraces-static PROPERTIES OUTPUT_NAME libctraces)
else()
  set_target_properties(ctraces-static PROPERTIES OUTPUT_NAME ctraces)
endif(MSVC)

install(TARGETS ctraces-static
  RUNTIME DESTINATION ${CTR_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CTR_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CTR_INSTALL_LIBDIR}
  COMPONENT library)

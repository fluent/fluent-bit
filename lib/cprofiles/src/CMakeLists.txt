set(src
  cprofiles.c
  cprof_attribute_unit.c
  cprof_function.c
  cprof_instrumentation_scope.c
  cprof_line.c
  cprof_link.c
  cprof_location.c
  cprof_mapping.c
  cprof_profile.c
  cprof_resource_profiles.c
  cprof_resource.c
  cprof_sample.c
  cprof_scope_profiles.c
  cprof_decode_opentelemetry.c
  cprof_encode_opentelemetry.c
  cprof_encode_text.c
  cprof_encode_msgpack.c
  cprof_decode_msgpack.c
  cprof_mpack_utils.c
  )

set(src
  ${src}
  )

# Static Library
add_library(cprofiles-static STATIC ${src})
target_link_libraries(cprofiles-static mpack-static cfl-static fluent-otel-proto)

# Install Library
if(MSVC)
  # Rename the output for Windows environment to avoid naming issues
  set_target_properties(cprofiles-static PROPERTIES OUTPUT_NAME libcprofiles)
else()
  set_target_properties(cprofiles-static PROPERTIES OUTPUT_NAME cprofiles)
endif(MSVC)

install(TARGETS cprofiles-static
  RUNTIME DESTINATION ${CPROF_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CPROF_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CPROF_INSTALL_LIBDIR}
  COMPONENT library)

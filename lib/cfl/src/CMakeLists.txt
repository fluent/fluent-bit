set(src
  cfl.c
  cfl_log.c
  cfl_sds.c
  cfl_time.c
  cfl_kv.c
  cfl_kvlist.c
  cfl_array.c
  cfl_variant.c
  cfl_checksum.c
  )

# Static Library
add_library(cfl-static STATIC ${src})
target_link_libraries(cfl-static xxhash)

# Install Library
if(MSVC)
  # Rename the output for Windows environment to avoid naming issues
  set_target_properties(cfl-static PROPERTIES OUTPUT_NAME libcfl)
else()
  set_target_properties(cfl-static PROPERTIES OUTPUT_NAME cfl)
endif(MSVC)

install(TARGETS cfl-static
  RUNTIME DESTINATION ${CFL_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CFL_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CFL_INSTALL_LIBDIR}
  COMPONENT library)

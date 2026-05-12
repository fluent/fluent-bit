set(src
  cfl.c
  cfl_log.c
  cfl_sds.c
  cfl_time.c
  cfl_kv.c
  cfl_kvlist.c
  cfl_object.c
  cfl_array.c
  cfl_variant.c
  cfl_container.c
  cfl_checksum.c
  cfl_utils.c
  )

set(CFL_ATOMIC_NEEDS_THREADS Off)

if(MSVC)
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_msvc.c)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_clang.c)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_clang.c)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_gcc.c)
else()
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_generic.c)
  set(CFL_ATOMIC_NEEDS_THREADS On)
endif()

set(src
  ${src}
  ${PLATFORM_SPECIFIC_ATOMIC_MODULE}
  )

# Static Library
add_library(cfl-static STATIC ${src})
target_link_libraries(cfl-static PRIVATE xxhash)

if(CFL_ATOMIC_NEEDS_THREADS)
  find_package(Threads REQUIRED)
  target_link_libraries(cfl-static PUBLIC Threads::Threads)
endif()

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

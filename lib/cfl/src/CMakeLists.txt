include(CheckCSourceCompiles)

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
  cfl_arena.c
  cfl_container.c
  cfl_checksum.c
  cfl_utils.c
  )

set(CFL_ATOMIC_NEEDS_THREADS Off)
set(CFL_ATOMIC_NEEDS_LIBATOMIC Off)
set(CFL_ATOMIC_USES_BUILTINS Off)

set(CFL_ATOMIC_BUILTINS_LINK_SOURCE "
  #include <stdint.h>
  int main(void) {
     uint64_t storage = 0;
     uint64_t expected = 0;
     uint64_t desired = 1;
     __atomic_store_n(&storage, desired, __ATOMIC_SEQ_CST);
     (void) __atomic_load_n(&storage, __ATOMIC_SEQ_CST);
     (void) __atomic_compare_exchange(&storage, &expected, &desired, 0,
                                      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
     return 0;
  }")

if("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_msvc.c)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_clang.c)
  set(CFL_ATOMIC_USES_BUILTINS On)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_clang.c)
  set(CFL_ATOMIC_USES_BUILTINS On)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_gcc.c)
  set(CFL_ATOMIC_USES_BUILTINS On)
else()
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_generic.c)
  set(CFL_ATOMIC_NEEDS_THREADS On)
endif()

if(CFL_ATOMIC_USES_BUILTINS)
  check_c_source_compiles("${CFL_ATOMIC_BUILTINS_LINK_SOURCE}"
                          CFL_ATOMIC_BUILTINS_LINK)

  if(NOT CFL_ATOMIC_BUILTINS_LINK)
    set(CFL_ATOMIC_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
    set(CMAKE_REQUIRED_LIBRARIES ${CFL_ATOMIC_REQUIRED_LIBRARIES})
    list(APPEND CMAKE_REQUIRED_LIBRARIES atomic)

    check_c_source_compiles("${CFL_ATOMIC_BUILTINS_LINK_SOURCE}"
                            CFL_ATOMIC_BUILTINS_LINK_WITH_LIBATOMIC)

    set(CMAKE_REQUIRED_LIBRARIES "${CFL_ATOMIC_REQUIRED_LIBRARIES}")

    if(CFL_ATOMIC_BUILTINS_LINK_WITH_LIBATOMIC)
      set(CFL_ATOMIC_NEEDS_LIBATOMIC On)
    elseif(CFL_SYSTEM_WINDOWS AND "${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
      set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_msvc.c)
    else()
      set(PLATFORM_SPECIFIC_ATOMIC_MODULE cfl_atomic_generic.c)
      set(CFL_ATOMIC_NEEDS_THREADS On)
    endif()
  endif()
endif()

set(src
  ${src}
  ${PLATFORM_SPECIFIC_ATOMIC_MODULE}
  )

# Static Library
add_library(cfl-static STATIC ${src})
set_target_properties(cfl-static PROPERTIES
  C_STANDARD ${CMAKE_C_STANDARD}
  C_STANDARD_REQUIRED On
  C_EXTENSIONS On)
target_link_libraries(cfl-static PUBLIC xxhash)

if(CFL_ATOMIC_NEEDS_LIBATOMIC)
  target_link_libraries(cfl-static PUBLIC atomic)
endif()

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

if(CFL_BUNDLED_XXHASH AND CFL_INSTALL_BUNDLED_XXHASH_HEADERS)
  install(TARGETS xxhash
    ARCHIVE DESTINATION ${CFL_INSTALL_LIBDIR}
    COMPONENT library)
endif()

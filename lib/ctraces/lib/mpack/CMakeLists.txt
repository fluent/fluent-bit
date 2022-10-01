set(src
  src/mpack/mpack.c
  )

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
add_definitions(-DMPACK_EXTENSIONS=1)
add_library(mpack-static STATIC ${src})

# Install Library
if(MSVC)
  # Rename the output for Windows environment to avoid naming issues
  set_target_properties(mpack-static PROPERTIES OUTPUT_NAME libmpack)
else()
  set_target_properties(mpack-static PROPERTIES OUTPUT_NAME mpack)
endif(MSVC)

# Installation Directories
# ========================
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(MPACK_INSTALL_LIBDIR "lib")
  set(MPACK_INSTALL_INCLUDEDIR "include")
else()
  set(MPACK_INSTALL_LIBDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
  set(MPACK_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif()

install(TARGETS mpack-static
  RUNTIME DESTINATION ${MPACK_INSTALL_BINDIR}
  LIBRARY DESTINATION ${MPACK_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${MPACK_INSTALL_LIBDIR}
  COMPONENT library)

set(src
  cio_os.c
  cio_log.c
  cio_file.c
  cio_memfs.c
  cio_chunk.c
  cio_meta.c
  cio_scan.c
  cio_utils.c
  cio_stream.c
  cio_stats.c
  cio_error.c
  chunkio.c
  )

set(libs cio-crc32)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(src
    ${src}
    cio_file_win32.c
    win32/dirent.c
    )
  set(libs
    ${libs}
    Shell32.lib)
else()
  set(src
    ${src}
    cio_file_unix.c
    )
endif()

if(CIO_LIB_STATIC)
  add_library(chunkio-static STATIC ${src})
  target_link_libraries(chunkio-static ${libs})
  if(CIO_SANITIZE_ADDRESS)
    add_sanitizers(chunkio-static)
  endif()
endif()

if (CIO_LIB_SHARED)
  add_library(chunkio-shared SHARED ${src})
  target_link_libraries(chunkio-shared ${libs})
  if(CIO_SANITIZE_ADDRESS)
    add_sanitizers(chunkio-shared)
  endif()
endif()

if (NOT CIO_LIB_STATIC AND NOT CIO_LIB_SHARED)
  message(FATAL_ERROR "What are you doing?, you should build something")
endif()

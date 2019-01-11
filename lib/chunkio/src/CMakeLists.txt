set(src
  cio_os.c
  cio_log.c
  cio_memfs.c
  cio_chunk.c
  cio_meta.c
  cio_scan.c
  cio_utils.c
  cio_stream.c
  chunkio.c
  )

if(CIO_BACKEND_FILESYSTEM)
  set(src
    ${src}
    cio_file.c
    )
else()
  set(src
    ${src}
    cio_file_compat.c
    )
endif()

if(CIO_LIB_STATIC)
  add_library(chunkio-static STATIC ${src})
  target_link_libraries(chunkio-static cio-crc32)
  if(CIO_SANITIZE_ADDRESS)
    add_sanitizers(chunkio-static)
  endif()
endif()

if (CIO_LIB_SHARED)
  add_library(chunkio-shared SHARED ${src})
  target_link_libraries(chunkio-static cio-crc32)
  if(CIO_SANITIZE_ADDRESS)
    add_sanitizers(chunkio-shared)
  endif()
endif()

if (NOT CIO_LIB_STATIC AND NOT CIO_LIB_SHARED)
  message(FATAL_ERROR "What are you doing?, you should build something")
endif()

set(src
  libco.c
  )

# Check for posix_memalign so that Apple Silicon can be supported
include(CheckSymbolExists)
check_symbol_exists(posix_memalign "stdint.h" HAVE_POSIX_MEMALIGN)
IF(HAVE_POSIX_MEMALIGN)
  add_definitions(-DHAVE_POSIX_MEMALIGN)
  MESSAGE("Found posix_memalign setting -DHAVE_POSIX_MEMALIGN")
ENDIF(HAVE_POSIX_MEMALIGN)

add_definitions(-DLIBCO_MP)
add_library(co STATIC ${src})

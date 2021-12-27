set(src
  libco.c
  )

include(CheckSymbolExists)

# Check for posix_memalign so that Apple Silicon can be supported
check_symbol_exists(posix_memalign "stdlib.h" HAVE_POSIX_MEMALIGN_IN_STDLIB)

IF(HAVE_POSIX_MEMALIGN_IN_STDLIB)
  # We need HAVE_POSIX_MEMALIGN for the ifdefs to use posix_memalign
  # We defined HAVE_POSIX_MEMALIGN_IN_STDLIB in order to avoid including in malloc.h
  add_definitions(-DHAVE_POSIX_MEMALIGN_IN_STDLIB -DHAVE_POSIX_MEMALIGN)
  MESSAGE("Found posix_memalign in stdlib.h -DHAVE_POSIX_MEMALIGN_IN_STDLIB -DHAVE_POSIX_MEMALIGN")
ENDIF(HAVE_POSIX_MEMALIGN_IN_STDLIB)

# Check for posix_memalign so that FreeBSD can be supported
check_symbol_exists(posix_memalign "malloc_np.h" HAVE_POSIX_MEMALIGN_IN_PTHREAD_NP)

IF(HAVE_POSIX_MEMALIGN_IN_PTHREAD_NP)
  # We need HAVE_POSIX_MEMALIGN for the ifdefs to use posix_memalign
  # We defined DHAVE_POSIX_MEMALIGN_IN_PTHREAD_NP in order to include malloc_np.h
  add_definitions(-DHAVE_POSIX_MEMALIGN_IN_PTHREAD_NP -DHAVE_POSIX_MEMALIGN)
  MESSAGE("Found posix_memalign in malloc_np.h -DHAVE_POSIX_MEMALIGN_IN_PTHREAD_NP -DHAVE_POSIX_MEMALIGN")
ENDIF(HAVE_POSIX_MEMALIGN_IN_PTHREAD_NP)

add_definitions(-DLIBCO_MP)
add_library(co STATIC ${src})

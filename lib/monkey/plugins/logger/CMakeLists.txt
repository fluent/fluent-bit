set(src
  pointers.c
  logger.c
  )

# Validate splice()
check_c_source_compiles("
  #define _GNU_SOURCE
  #include <stdio.h>
  #include <fcntl.h>
  int main() {
     return splice(0, NULL, 1,
            NULL, 1, SPLICE_F_MOVE);
  }" HAVE_SPLICE)

if (HAVE_SPLICE)
  add_definitions(-DHAVE_SPLICE)
endif()

MONKEY_PLUGIN(logger "${src}")
add_subdirectory(conf)

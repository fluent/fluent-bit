set(src
  pointers.c
  logger.c
  )

MONKEY_PLUGIN(logger "${src}")
add_subdirectory(conf)

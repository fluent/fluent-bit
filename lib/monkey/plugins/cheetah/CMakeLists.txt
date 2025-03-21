set(src
  cheetah.c
  loop.c
  cmd.c
  cutils.c
  )

MONKEY_PLUGIN(cheetah "${src}")
add_subdirectory(conf)

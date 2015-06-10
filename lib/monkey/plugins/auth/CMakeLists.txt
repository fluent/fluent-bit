set(src
  auth.c
  base64.c
  conf.c
  sha1.c
  )

add_subdirectory(tools)

MONKEY_PLUGIN(auth "${src}")

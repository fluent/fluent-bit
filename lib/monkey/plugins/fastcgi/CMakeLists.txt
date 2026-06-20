set(src
  fastcgi.c
  fcgi_handler.c
  )

MONKEY_PLUGIN(fastcgi "${src}")
add_subdirectory(conf)

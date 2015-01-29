set(src
  mk_string.c
  mk_config.c
)

include_directories(mk_config/)
add_library(mk_config STATIC ${src})

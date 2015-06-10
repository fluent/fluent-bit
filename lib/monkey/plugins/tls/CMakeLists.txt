set(src
  tls.c
)

MONKEY_PLUGIN(tls "${src}")
MONKEY_PLUGIN_LINK_LIB(tls mbedtls)
add_subdirectory(conf)

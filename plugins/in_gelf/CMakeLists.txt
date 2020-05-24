set(src
  gelf.c
  gelf_conn.c
  gelf_config.c)

FLB_PLUGIN(in_gelf "${src}" "")

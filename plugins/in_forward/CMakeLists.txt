set(src
  fw.c
  fw_conn.c
  fw_prot.c
  fw_config.c)

FLB_PLUGIN(in_forward "${src}" "")

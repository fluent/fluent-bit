set(src
  remote_write.c
  remote_write_conf.c
  )

FLB_PLUGIN(out_prometheus_remote_write "${src}" "")

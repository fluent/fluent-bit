set(src
  syslog.c
  syslog_conf.c)

FLB_PLUGIN(out_syslog "${src}" "")

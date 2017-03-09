set(src
  syslog_conf.c
  syslog_unix.c
  syslog_conn.c
  syslog_prot.c
  syslog.c)

FLB_PLUGIN(in_syslog "${src}" "")

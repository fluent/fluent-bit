set(src
  systemd_config.c
  systemd_db.c
  systemd.c)

FLB_PLUGIN(in_systemd "${src}" ${JOURNALD_LIBRARIES})

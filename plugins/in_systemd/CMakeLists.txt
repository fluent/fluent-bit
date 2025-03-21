set(src
  systemd_config.c
  systemd.c)

if(FLB_SQLDB)
set(src
    ${src}
    systemd_db.c)
endif()

FLB_PLUGIN(in_systemd "${src}" ${JOURNALD_LIBRARIES})

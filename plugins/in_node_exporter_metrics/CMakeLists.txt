set(src
  ne_cpu.c
  ne_meminfo.c
  ne_diskstats.c
  ne_uname.c
  ne_stat_linux.c
  ne_vmstat_linux.c
  ne_netdev.c
  ne_time.c
  ne_loadavg.c
  ne_filefd_linux.c
  ne_utils.c
  ne_config.c
  ne.c
  )

FLB_PLUGIN(in_node_exporter_metrics "${src}" "")

set(src
  ne_cpu.c
  ne_meminfo.c
  ne_diskstats.c
  ne_filesystem.c
  ne_uname.c
  ne_stat.c
  ne_vmstat.c
  ne_netdev.c
  ne_sockstat.c
  ne_time.c
  ne_loadavg.c
  ne_filefd.c
  ne_textfile.c
  ne_processes.c
  ne_nvme.c
  ne_utils.c
  ne_config.c
  ne_systemd.c
  ne_thermalzone.c
  ne.c
  )

FLB_PLUGIN(in_node_exporter_metrics "${src}" "")

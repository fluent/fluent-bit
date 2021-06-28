set(src
  ne_cpu.c
  ne_meminfo.c
  ne_diskstats.c
  ne_utils.c
  ne_config.c
  ne.c
  )

FLB_PLUGIN(in_node_exporter_metrics "${src}" "")

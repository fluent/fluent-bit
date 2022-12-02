set(src
  we_config.c
  we.c
  we_cpu.c
  we_wmi.c
  we_util.c
  we_metric.c
  we_perflib.c
  we_wmi_thermalzone.c
  )

FLB_PLUGIN(in_windows_exporter_metrics "${src}" "wbemuuid")

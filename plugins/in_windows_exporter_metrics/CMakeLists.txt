set(src
  we_config.c
  we.c
  we_cpu.c
  we_os.c
  we_net.c
  we_logical_disk.c
  we_cs.c
  we_wmi.c
  we_util.c
  we_metric.c
  we_cache.c
  we_perflib.c
  we_wmi_thermalzone.c
  we_wmi_cpu_info.c
  we_wmi_logon.c
  we_wmi_system.c
  we_wmi_service.c
  we_wmi_memory.c
  we_wmi_paging_file.c
  we_wmi_process.c
  we_wmi_tcp.c
  )

set(libs
  wbemuuid
  netapi32
)

FLB_PLUGIN(in_windows_exporter_metrics "${src}" "${libs}")

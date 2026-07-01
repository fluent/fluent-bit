set(src
  pe.c
  pe_config.c
  pe_process.c
  pe_utils.c
  )

FLB_PLUGIN(in_process_exporter_metrics "${src}" "")
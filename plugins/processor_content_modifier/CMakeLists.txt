set(src
  cm_config.c
  cm_logs.c
  cm_metrics.c
  cm_traces.c
  cm_opentelemetry.c
  cm_utils.c
  cm.c
  )

FLB_PLUGIN(processor_content_modifier "${src}" "")

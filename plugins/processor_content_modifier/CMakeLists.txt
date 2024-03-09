set(src
  cm_config.c
  cm_logs.c
  cm.c
  )

FLB_PLUGIN(processor_content_modifier "${src}" "")

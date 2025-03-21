if(NOT FLB_METRICS)
  message(FATAL_ERROR "Log Metrics filter plugin requires FLB_METRICS=On.")
endif()

set(src
  log_to_metrics.c)

FLB_PLUGIN(filter_log_to_metrics "${src}" "")

set(src
  cumulative_to_delta.c
  cumulative_to_delta_core.c)

FLB_PLUGIN(processor_cumulative_to_delta "${src}" "")

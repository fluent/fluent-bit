set(src
  adaptive.c
  adaptive_miner.c
  adaptive_policy.c
  adaptive_group.c
  adaptive_structured.c
  adaptive_summary.c
  adaptive_raw.c
  adaptive_state.c
  adaptive_report.c)

FLB_PLUGIN(processor_adaptive "${src}" "")

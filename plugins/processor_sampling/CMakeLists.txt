set(src
  sampling.c
  sampling_conf.c
  sampling_span_registry.c
  sampling_conditions.c
  sampling_cond_status_codes.c
  sampling_cond_latency.c

  # types of sampling
  #sampling_test.c
  sampling_tail.c
  sampling_probabilistic.c
)

FLB_PLUGIN(processor_sampling "${src}" "")

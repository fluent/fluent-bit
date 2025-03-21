set(src
  sampling.c
  sampling_conf.c
  sampling_span_registry.c

  # conditions
  sampling_conditions.c
  sampling_cond_status_codes.c
  sampling_cond_latency.c
  sampling_cond_attribute.c
  sampling_cond_string_attribute.c
  sampling_cond_numeric_attribute.c
  sampling_cond_boolean_attribute.c
  sampling_cond_span_count.c
  sampling_cond_trace_state.c

  # types of sampling
  #sampling_test.c
  sampling_tail.c
  sampling_probabilistic.c
)

FLB_PLUGIN(processor_sampling "${src}" "")

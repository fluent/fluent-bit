set(src
  sampling.c
  sampling_conf.c
  sampling_span_registry.c

  # types of sampling
  sampling_test.c
  sampling_probabilistic.c
)

FLB_PLUGIN(processor_sampling "${src}" "")

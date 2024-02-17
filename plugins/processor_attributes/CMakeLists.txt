set(src
  attributes.c
  traces.c
  variant_utils.c)

FLB_PLUGIN(processor_attributes "${src}" "")

set(src
  gce_metadata.c
  stackdriver_conf.c
  stackdriver.c
  )

FLB_PLUGIN(out_stackdriver "${src}" "")

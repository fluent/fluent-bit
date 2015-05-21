set(src
  ../../src/flb_network.c
  fluentd.c)

FLB_PLUGIN(out_fluentd "${src}" "")

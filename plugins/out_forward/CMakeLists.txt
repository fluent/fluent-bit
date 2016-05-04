set(src
  ../../src/flb_network.c
  forward.c)

FLB_PLUGIN(out_forward "${src}" "")

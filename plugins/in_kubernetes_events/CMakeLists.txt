set(src
  kubernetes_events_conf.c
  kubernetes_events.c)

FLB_PLUGIN(in_kubernetes_events "${src}" "")

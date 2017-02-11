set(src
  kube_conf.c
  kube_meta.c
  kubernetes.c
  )

FLB_PLUGIN(filter_kubernetes "${src}" "")

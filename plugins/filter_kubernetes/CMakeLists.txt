set(src
  kube_conf.c
  kube_meta.c
  kube_regex.c
  kube_property.c
  kubernetes.c
  )

FLB_PLUGIN(filter_kubernetes "${src}" "")

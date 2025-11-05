set(src
  kube_conf.c
  kube_meta.c
  kube_regex.c
  kube_property.c
  kubernetes.c
  kubernetes_aws.c
  )

FLB_PLUGIN(filter_kubernetes "${src}" "")

# K8s token command is currently Linux-only.
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  FLB_DEFINITION(FLB_HAVE_KUBE_TOKEN_COMMAND)
endif()
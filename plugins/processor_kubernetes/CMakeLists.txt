set(src
  kubernetes.c
  ../filter_kubernetes/kube_meta.c
  ../filter_kubernetes/kube_regex.c
  ../filter_kubernetes/kube_property.c
  ../filter_kubernetes/kubernetes_aws.c
  )

FLB_PLUGIN(processor_kubernetes "${src}" "")

target_compile_definitions(flb-plugin-processor_kubernetes PRIVATE
  flb_kube_regex_init=flb_processor_kube_regex_init
  flb_kube_meta_init=flb_processor_kube_meta_init
  flb_kube_meta_fetch=flb_processor_kube_meta_fetch
  flb_kube_dummy_meta_get=flb_processor_kube_dummy_meta_get
  flb_kube_meta_get=flb_processor_kube_meta_get
  flb_kube_meta_release=flb_processor_kube_meta_release
  flb_kube_pod_association_init=flb_processor_kube_pod_association_init
  get_api_server_configmap=processor_kube_get_api_server_configmap
  flb_kube_prop_set=flb_processor_kube_prop_set
  flb_kube_prop_pack=flb_processor_kube_prop_pack
  flb_kube_prop_unpack=flb_processor_kube_prop_unpack
  flb_kube_prop_destroy=flb_processor_kube_prop_destroy
  fetch_pod_service_map=processor_kube_fetch_pod_service_map
  determine_platform=processor_kube_determine_platform
  get_cluster_from_environment=processor_kube_get_cluster_from_environment
  )

# K8s token command is currently Linux-only.
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  FLB_DEFINITION(FLB_HAVE_KUBE_TOKEN_COMMAND)
endif()

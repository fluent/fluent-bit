set(src
  azure_conf.c
  azure.c
  )

FLB_PLUGIN(out_azure "${src}" "")

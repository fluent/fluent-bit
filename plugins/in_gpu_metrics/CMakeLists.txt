set(src
  gpu_metrics.c
  amd_gpu.c
  gpu_common.c
)

FLB_PLUGIN(in_gpu_metrics "${src}" "")

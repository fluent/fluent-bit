set(src
  podman_metrics.c
  podman_metrics_data.c
  )

FLB_PLUGIN(in_podman_metrics "${src}" "")

set(src
  docker.c
  cgroup_v1.c
  cgroup_v2.c
  )

FLB_PLUGIN(in_docker "${src}" "")

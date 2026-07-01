set(src
  docker_events.c
  docker_events_config.c)

FLB_PLUGIN(in_docker_events "${src}" "")

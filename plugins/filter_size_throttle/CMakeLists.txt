set(src
  size_window.c
  size_throttle.c
  )

FLB_PLUGIN(filter_size_throttle "${src}" "")

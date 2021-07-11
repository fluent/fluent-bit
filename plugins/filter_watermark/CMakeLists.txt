set(src
  heap.c
  watermark.c
  )

FLB_PLUGIN(filter_watermark "${src}" "")

set(src
  sb.c
  )

FLB_PLUGIN(in_storage_backlog "${src}" "chunkio-static")

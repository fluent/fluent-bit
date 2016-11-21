set(src
  tail_file.c
  tail_scan.c
  tail_config.c
  tail_fs.c
  tail.c)

FLB_PLUGIN(in_tail "${src}" "")

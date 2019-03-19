set(src
  tail_file.c
  tail_dockermode.c
  tail_scan.c
  tail_config.c
  tail_db.c
  tail_fs.c
  tail.c)

if(FLB_PARSER)
  set(src
    ${src}
    tail_multiline.c
    )
endif()

FLB_PLUGIN(in_tail "${src}" "")

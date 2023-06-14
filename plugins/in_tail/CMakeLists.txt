set(src
  tail_file.c
  tail_dockermode.c
  tail_scan.c
  tail_config.c
  tail_fs_stat.c
  tail.c)

if(FLB_HAVE_INOTIFY)
set(src
    ${src}
    tail_fs_inotify.c)
endif()

if(FLB_SQLDB)
set(src
    ${src}
    tail_db.c)
endif()

if(FLB_PARSER)
  set(src
    ${src}
    tail_multiline.c
    )
endif()

if(MSVC)
  FLB_PLUGIN(in_tail "${src}" "Shlwapi")
else()
  FLB_PLUGIN(in_tail "${src}" "")
endif()

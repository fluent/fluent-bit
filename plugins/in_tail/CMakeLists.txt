set(src
  tail_file.c
  tail_dockermode.c
  tail_scan.c
  tail_config.c
  tail_fs.c
  tail.c)

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
  set(src
    ${src}
    win32/stat.c
    win32/io.c
    )
  FLB_PLUGIN(in_tail "${src}" "Shlwapi")
else()
  FLB_PLUGIN(in_tail "${src}" "")
endif()

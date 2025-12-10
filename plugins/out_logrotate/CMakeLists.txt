set(src
  logrotate.c)

if(MSVC)
  FLB_PLUGIN(out_logrotate "${src}" "Shlwapi")
else()
  FLB_PLUGIN(out_logrotate "${src}" "")
endif()

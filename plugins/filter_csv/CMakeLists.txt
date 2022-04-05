set(src
  csv.c)

if(MSVC)
  FLB_PLUGIN(filter_csv "${src}" "")
else()
  FLB_PLUGIN(filter_csv "${src}" "m")
endif()

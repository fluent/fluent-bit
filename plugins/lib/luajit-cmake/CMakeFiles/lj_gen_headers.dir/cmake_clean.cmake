file(REMOVE_RECURSE
  "CMakeFiles/lj_gen_headers"
  "jit/vmdef.lua"
  "lj_bcdef.h"
  "lj_ffdef.h"
  "lj_libdef.h"
  "lj_recdef.h"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/lj_gen_headers.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()

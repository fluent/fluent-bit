# FIXME: there is something wrong when linking objects and this
# static plugin, I should not require to link to a specific symbol
# if the object was already linked from fluent-bit core on src/, also
# jsmn should not be required.

set(src
  in_lib.c
  ../../src/flb_pack.c)

FLB_PLUGIN(in_lib "${src}" "jsmn")

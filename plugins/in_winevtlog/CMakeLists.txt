set(src
    in_winevtlog.c
    pack.c
    winevtlog.c)

FLB_PLUGIN(in_winevtlog "${src}" "wevtapi")

set(src
    in_winlog.c
    pack.c
    winlog.c)

FLB_PLUGIN(in_winlog "${src}" "advapi32")

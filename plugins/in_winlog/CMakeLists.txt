set(src
    in_winlog.c
    winlog.c)

FLB_PLUGIN(in_winlog "${src}" "advapi32")

set(src
    etw.c)

FLB_PLUGIN(in_etw "${src}" "advapi32;tdh;ole32")

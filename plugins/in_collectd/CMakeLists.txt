set(src
    typesdb.c
    typesdb_parser.c
    netprot.c
    in_collectd.c)

FLB_PLUGIN(in_collectd "${src}" "")

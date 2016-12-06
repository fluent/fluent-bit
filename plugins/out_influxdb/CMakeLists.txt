set(src
  influxdb_bulk.c
  influxdb.c)

FLB_PLUGIN(out_influxdb "${src}" "")

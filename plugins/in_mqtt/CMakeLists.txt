set(src
  mqtt.c
  mqtt_conn.c
  mqtt_prot.c)

FLB_PLUGIN(in_mqtt "${src}" "")

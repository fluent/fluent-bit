set(src
  in_mqtt.c
  mqtt_conn.c)

FLB_PLUGIN(in_mqtt "${src}" "")

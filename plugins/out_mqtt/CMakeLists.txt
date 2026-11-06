set(src
  mqtt.c
  mqtt_conf.c
  mqtt_prot.c
  )

FLB_PLUGIN(out_mqtt "${src}" "")

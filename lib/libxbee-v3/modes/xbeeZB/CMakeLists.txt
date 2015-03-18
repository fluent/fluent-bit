set(src
  at.c
  data.c
  dataExp.c
  identify.c
  io.c
  mode.c
  ota.c
  sensor.c
  ../common.c
  ../../xsys.c
  )

add_library(xbeeZB_mode ${src})

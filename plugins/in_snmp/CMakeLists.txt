set(NETSNMP_LIBRARIES ${NETSNMP_LIBRARY})
set(NETSNMP_INCLUDE_DIRS ${NETSNMP_INCLUDE_DIR})

set(src
  in_snmp.c)

FLB_PLUGIN(in_snmp "${src}" "")
target_link_libraries(flb-plugin-in_snmp ${NETSNMP_LIBRARIES})
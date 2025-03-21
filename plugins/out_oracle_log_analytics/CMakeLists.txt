set(src
   oci_logan.c
   oci_logan_conf.c
   )

FLB_PLUGIN(out_oracle_log_analytics "${src}" "")

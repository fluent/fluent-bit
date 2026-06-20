set(src
  splunk_conf.c
  splunk.c
  )

FLB_PLUGIN(out_splunk "${src}" "")

set(src
  gce_metadata.c
  stackdriver_conf.c
  stackdriver.c
  stackdriver_operation.c
  stackdriver_source_location.c
  stackdriver_http_request.c
  stackdriver_timestamp.c
  stackdriver_helper.c
  stackdriver_resource_types.c
  )

FLB_PLUGIN(out_stackdriver "${src}" "")

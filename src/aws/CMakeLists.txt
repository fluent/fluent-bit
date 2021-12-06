add_subdirectory(compression)

set(src
  "flb_aws_credentials_log.h"
  "flb_aws_compress.c"
  "flb_aws_util.c"
  "flb_aws_credentials.c"
  "flb_aws_credentials_sts.c"
  "flb_aws_credentials_ec2.c"
  "flb_aws_imds.c"
  "flb_aws_credentials_http.c"
  "flb_aws_credentials_profile.c"
  )

if(FLB_HAVE_AWS_CREDENTIAL_PROCESS)
  set(src
    ${src}
    "flb_aws_credentials_process.c"
    )
endif()

if (FLB_AWS_ERROR_REPORTER)
  set(src
    ${src}
    "flb_aws_error_reporter.c"
    )
endif()

add_library(flb-aws STATIC ${src})
target_link_libraries(flb-aws flb-aws-compress)

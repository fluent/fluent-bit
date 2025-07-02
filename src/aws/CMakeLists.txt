add_subdirectory(compression)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  )

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

if(FLB_KAFKA AND FLB_HAVE_KAFKA_SASL)
  set(src
    ${src}
    "flb_aws_msk_iam.c"
    )
else()
  FLB_DEFINITION(FLB_HAVE_AWS_MSK_IAM)
endif()

if(FLB_HAVE_AWS_CREDENTIAL_PROCESS)
  set(src
    ${src}
    "flb_aws_credentials_process.c"
    )
endif()

add_library(flb-aws STATIC ${src})
target_link_libraries(flb-aws flb-aws-compress)

if(FLB_JEMALLOC)
  target_link_libraries(flb-aws ${JEMALLOC_LIBRARIES})
endif()

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
  "flb_aws_credentials_iot.c"
  )

message(STATUS "=== AWS Credentials ===")

# AWS MSK IAM - use the definition from root CMakeLists.txt
if(DEFINED FLB_HAVE_AWS_MSK_IAM)
  set(src
    ${src}
    "flb_aws_msk_iam.c"
    )
  message(STATUS "- AWS MSK IAM authentication: ENABLED")
else()
  message(STATUS "- AWS MSK IAM authentication: DISABLED")
endif()

if(FLB_HAVE_AWS_CREDENTIAL_PROCESS)
  set(src
    ${src}
    "flb_aws_credentials_process.c"
    )
  message(STATUS "- AWS Credential Process: ENABLED")
else()
  message(STATUS "- AWS Credential Process: DISABLED")
endif()

message(STATUS "===========================")

add_library(flb-aws STATIC ${src})
target_link_libraries(flb-aws flb-aws-compress)

# Link rdkafka when MSK IAM is enabled
if(DEFINED FLB_HAVE_AWS_MSK_IAM AND KAFKA_LIBRARIES)
  target_link_libraries(flb-aws ${KAFKA_LIBRARIES})
endif()

if(FLB_JEMALLOC)
  target_link_libraries(flb-aws ${JEMALLOC_LIBRARIES})
endif()

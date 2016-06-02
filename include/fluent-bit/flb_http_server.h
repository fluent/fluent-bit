#ifndef FLB_HTTP_H
#define FLB_HTTP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_version.h>

#define FLB_HTTP_BANNER \
  "{\n  \"service\"  : \"Fluent Bit\",\n" \
  "  \"version\": \"v" FLB_VERSION_STR "\",\n" \
  "  \"build_flags\": \"" FLB_INFO_FLAGS "\"\n}"

int flb_http_server_start(struct flb_config *config);

#endif

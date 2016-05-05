#ifndef FLB_HTTP_H
#define FLB_HTTP_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_version.h>

#define FLB_HTTP_BANNER "Fluent Bit v" FLB_VERSION_STR " is running!"

int flb_http_server_start(struct flb_config *config);

#endif

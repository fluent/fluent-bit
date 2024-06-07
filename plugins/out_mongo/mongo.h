#ifndef FLB_OUT_MONGO_H
#define FLB_OUT_MONGO_H

#include <fluent-bit/flb_time.h>

#define FLB_MONGODB_HOST "127.0.0.1"
#define FLB_MONGODB_PORT 27017

struct flb_mongodb {

  char uri[1024];

  struct flb_upstream* upstream;

  flb_sds_t http_user;
  flb_sds_t http_passwd;
  flb_sds_t http_token;
  struct mk_list *headers;

  struct flb_time ts_dupe;
  struct flb_time ts_last;

  struct flb_output_instance *instance;
};

#endif // FLB_OUT_MONGO_H

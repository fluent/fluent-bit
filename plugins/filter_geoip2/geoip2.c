/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <stdio.h>
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_regex.h>
#include <msgpack.h>

#include "geoip2.h"

static int cb_geoip2_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data)
{
  return 0;
}

static int cb_geoip2_filter(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            void **out_buf, size_t *out_size,
                            struct flb_filter_instance *f_ins,
                            void *context,
                            struct flb_config *config)
{
  return 0;
}

static int cb_geoip2_exit(void *data, struct flb_config *config)
{
  return 0;
}

struct flb_filter_plugin filter_geoip2_plugin = {
    .name = "geoip2",
    .description = "add geoip information to records",
    .cb_init = cb_geoip2_init,
    .cb_filter = cb_geoip2_filter,
    .cb_exit = cb_geoip2_exit,
    .flags = 0,
};

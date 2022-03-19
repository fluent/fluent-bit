/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>

#include "flb_fuzz_header.h"

struct context {
    /* Single values */
    int num_int;
    size_t size;
    time_t time;
    char boolean;
    double num_double;
    flb_sds_t string;
    struct mk_list *list1;
    struct mk_list *list2;

    /* Multiple entries */
    struct mk_list *mult_num_int;
    struct mk_list *mult_boolean;
    struct mk_list *mult_num_double;
    struct mk_list *mult_string;
    struct mk_list *mult_list1;
    struct mk_list *mult_list2;
};

struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL,
     "boolean",
     "true",
     0, FLB_TRUE, offsetof(struct context, boolean),
     NULL
    },
    {
     FLB_CONFIG_MAP_INT,
     "num_int",
     "123",
     0, FLB_TRUE, offsetof(struct context, num_int),
     NULL
    },
    {
     FLB_CONFIG_MAP_DOUBLE,
     "num_double", "0.12345",
     0, FLB_TRUE, offsetof(struct context, num_double),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR,
     "string",
     "test",
     0, FLB_TRUE, offsetof(struct context, string),
     NULL
    },

    /* SIZE */
    {
     FLB_CONFIG_MAP_SIZE,
     "test_size",
     "2M",
     0, FLB_TRUE, offsetof(struct context, size),
     NULL
    },

    /* TIME */
    {
     FLB_CONFIG_MAP_TIME,
     "test_time",
     "2H",
     0, FLB_TRUE, offsetof(struct context, time),
     NULL
    },

    /* CSLIST */
    {
     FLB_CONFIG_MAP_CLIST,
     "test_clist",
     "a,  b, c      ,d,e   ,    f,   g,h,i,jk   , lm  , n  o,pqr,,   , ,stuv,xyz",
     0, FLB_TRUE, offsetof(struct context, list1),
     NULL
    },

    /* SLIST */
    {
     FLB_CONFIG_MAP_SLIST_4,
     "test_slist",
     "a  b c      de       f   ghi jk l m n  o pqr   stuv xyz",
     0, FLB_TRUE, offsetof(struct context, list2),
     NULL
    },

     /* EOF */
    {0}
};

struct flb_config_map config_map_mult[] = {
    {
     FLB_CONFIG_MAP_BOOL,
     "no_mult",
     "true",
     0, FLB_TRUE, 1,
     NULL
     },
    {
     FLB_CONFIG_MAP_BOOL,
     "mult_boolean",
     NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct context, mult_boolean),
     NULL
    },
    {
     FLB_CONFIG_MAP_INT,
     "mult_num_int",
     "123",
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct context, mult_num_int),
     NULL
    },
    {
     FLB_CONFIG_MAP_DOUBLE,
     "mult_num_double", "0.12345",
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct context, mult_num_double),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR,
     "mult_string",
     "test",
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct context, mult_string),
     NULL
    },
    {
     FLB_CONFIG_MAP_CLIST,
     "mult_clist",
     "a,  b, c      ,d,e   ,    f,   g,h,i,jk   , lm  , n  o,pqr,,   , ,stuv,xyz",
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct context, mult_list1),
     NULL
    },
    {
     FLB_CONFIG_MAP_SLIST_4,
     "mult_slist",
     "a  b c      de       f   ghi jk l m n  o pqr   stuv xyz",
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct context, mult_list2),
     NULL
    },

     /* EOF */
    {0}
};

struct flb_config_map *configs[] = {config_map_mult, config_map};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    flb_malloc_p = 0;
    if (size < 40) {
        return 0;
    }

    struct context ctx;
    struct mk_list *map;
    struct mk_list prop;
    struct flb_config *config;

    char *null_terminated1 = get_null_terminated(15, &data, &size);
    char *null_terminated2 = get_null_terminated(15, &data, &size);
    char *null_terminated3 = get_null_terminated(size, &data, &size);

    for (int i = 0; i < 2; i++) {
        config = flb_config_init();
        if (!config) {
            return 0;
        }
        memset(&ctx, '\0', sizeof(struct context));

        flb_kv_init(&prop);
        flb_kv_item_create(&prop, null_terminated1, null_terminated2);

        /* Assign one of the config maps */
        map = flb_config_map_create(config, configs[i]);
        flb_config_map_set(&prop, map,&ctx);
        flb_config_map_properties_check(null_terminated3, &prop, map);
        flb_config_map_destroy(map);
        flb_kv_release(&prop);
        flb_config_exit(config);
    }

    flb_free(null_terminated1);
    flb_free(null_terminated2);
    flb_free(null_terminated3);
    return 0;
}

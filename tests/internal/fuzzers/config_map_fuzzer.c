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
    int boolean;
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
    /* Set flb_malloc_mod to be fuzzer-data dependent */
    if (size < 4) {
        return 0;
    }
    flb_malloc_p = 0;
    flb_malloc_mod = *(int*)data;
    data += 4;
    size -= 4;

    /* Avoid division by zero for modulo operations */
    if (flb_malloc_mod == 0) {
        flb_malloc_mod = 1;
    }

    if (size < 40) {
        return 0;
    }

    struct mk_list *map = NULL;
    struct flb_config *config = NULL;
    struct context ctx;
    bzero(&ctx, sizeof(struct context));
    struct mk_list prop;
    bzero(&prop, sizeof(struct mk_list));

    char *fuzz_str1 = get_null_terminated(15, &data, &size);
    char *fuzz_str2 = get_null_terminated(15, &data, &size);
    char *fuzz_str3 = get_null_terminated(size, &data, &size);

    for (int i = 0; i < 2; i++) {
        config = flb_config_init();
        if (config) {
            memset(&ctx, '\0', sizeof(struct context));

            flb_kv_init(&prop);
            if (flb_kv_item_create(&prop, fuzz_str1, fuzz_str2) != NULL) {
                /* Assign one of the config maps */
                map = flb_config_map_create(config, configs[i]);
                if (map) {
                    if (flb_config_map_set(config, &prop, map, &ctx) != -1) {
                        flb_config_map_properties_check(fuzz_str3, &prop, map);
                    }
                    flb_config_map_destroy(map);
                }
            }
            flb_kv_release(&prop);
            flb_config_exit(config);
        }
    }

    flb_free(fuzz_str1);
    flb_free(fuzz_str2);
    flb_free(fuzz_str3);
    return 0;
}

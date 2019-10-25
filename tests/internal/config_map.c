/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_config_map.h>

#include "flb_tests_internal.h"

struct context {
    int boolean;
    int num_int;
    double num_double;
    flb_sds_t string;
    struct mk_list *list1;
    struct mk_list *list2;
};

struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL,
     "boolean",
     "true",
     offsetof(struct context, boolean),
     NULL
    },
    {
     FLB_CONFIG_MAP_INT,
     "num_int",
     "123",
     offsetof(struct context, num_int),
     NULL
    },
    {
     FLB_CONFIG_MAP_DOUBLE,
     "num_double", "0.12345",
     offsetof(struct context, num_double),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR,
     "string",
     "test",
     offsetof(struct context, string),
     NULL
    },

    {
     FLB_CONFIG_MAP_CLIST,
     "test_clist",
     "a,  b, c      ,d,e   ,    f,   g,h,i,jk   , lm  , n  o,pqr,,   , ,stuv,xyz",
     offsetof(struct context, list1),
     NULL
    },

    /* SLIST */
    {
     FLB_CONFIG_MAP_SLIST_4,
     "test_slist",
     "a  b c      de       f   ghi jk l m n  o pqr   stuv xyz",
     offsetof(struct context, list2),
     NULL
    },

     /* EOF */
    {0, NULL, NULL, 0, NULL}
};

void test_helper()
{
    int ret;
    struct context ctx;
    struct mk_list *map;
    struct mk_list prop;

    memset(&ctx, '\0', sizeof(struct context));

    /* Create invalid property */
    flb_kv_init(&prop);
    flb_kv_item_create(&prop, "bad", "property");

    map = flb_config_map_create(config_map);
    TEST_CHECK(map != NULL);

    ret = flb_config_map_properties_check("test", &prop, map);
    TEST_CHECK(ret == -1);

    flb_config_map_destroy(map);
    flb_kv_release(&prop);
}

void test_create()
{
    int ret;
    struct context ctx;
    struct mk_list *map;
    struct mk_list properties;
    struct flb_slist_entry *e;

    memset(&ctx, '\0', sizeof(struct context));
    mk_list_init(&properties);

    map = flb_config_map_create(config_map);
    TEST_CHECK(map != NULL);

    /* Populate default values only */
    ret = flb_config_map_set(&properties, map, &ctx);
    TEST_CHECK(ret == 0);

    TEST_CHECK(ctx.boolean == 1);
    TEST_CHECK(ctx.num_int == 123);
    TEST_CHECK(ctx.num_double == 0.12345);
    TEST_CHECK(strcmp(ctx.string, "test") == 0);
    TEST_CHECK(flb_sds_len(ctx.string) == 4);
    TEST_CHECK(mk_list_size(ctx.list1) == 15);
    TEST_CHECK(mk_list_size(ctx.list2) == 5);

    e = mk_list_entry_last(ctx.list2, struct flb_slist_entry, _head);
    TEST_CHECK(strcmp(e->str, "f   ghi jk l m n  o pqr   stuv xyz") == 0);
    flb_config_map_destroy(map);
}

void test_override_defaults()
{
    int ret;
    struct context ctx;
    struct mk_list *map;
    struct mk_list properties;
    struct flb_slist_entry *e;

    memset(&ctx, '\0', sizeof(struct context));
    mk_list_init(&properties);

    map = flb_config_map_create(config_map);
    TEST_CHECK(map != NULL);

    /* Create a properties list that will override default values */
    flb_kv_item_create(&properties, "boolean", "false");
    flb_kv_item_create(&properties, "num_int", "321");
    flb_kv_item_create(&properties, "num_double", "0.54321");
    flb_kv_item_create(&properties, "string", "no test");
    flb_kv_item_create(&properties, "test_clist", "abc, def, ghi ,,,,jkl  ");
    flb_kv_item_create(&properties, "test_slist", "abc def ghi jkl m n o");

    /* Populate default values only */
    ret = flb_config_map_set(&properties, map, &ctx);
    TEST_CHECK(ret == 0);

    TEST_CHECK(ctx.boolean == 0);
    TEST_CHECK(ctx.num_int == 321);
    TEST_CHECK(ctx.num_double == 0.54321);
    TEST_CHECK(strcmp(ctx.string, "no test") == 0);
    TEST_CHECK(flb_sds_len(ctx.string) == 7);
    TEST_CHECK(mk_list_size(ctx.list1) == 4);
    TEST_CHECK(mk_list_size(ctx.list2) == 5);

    e = mk_list_entry_last(ctx.list2, struct flb_slist_entry, _head);
    TEST_CHECK(strcmp(e->str, "m n o") == 0);

    flb_kv_release(&properties);
    flb_config_map_destroy(map);
}

TEST_LIST = {
    { "helper"           , test_helper},
    { "create"           , test_create},
    { "override_defaults", test_override_defaults},
    { 0 }
};

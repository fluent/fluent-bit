/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>

#include "flb_tests_internal.h"

struct context {
    /* Single values */
    int num_int;
    size_t size;
    int time;
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

void test_helper()
{
    int ret;
    struct context ctx;
    struct mk_list *map;
    struct mk_list prop;
    struct flb_config *config;

    config = flb_config_init();
    if (!config) {
        exit(1);
    }

    memset(&ctx, '\0', sizeof(struct context));

    /* Create invalid property */
    flb_kv_init(&prop);
    flb_kv_item_create(&prop, "bad", "property");

    map = flb_config_map_create(config, config_map);
    TEST_CHECK(map != NULL);

    ret = flb_config_map_properties_check("test", &prop, map);
    TEST_CHECK(ret == -1);

    flb_config_map_destroy(map);
    flb_kv_release(&prop);

    flb_config_exit(config);
}

void test_create()
{
    int ret;
    struct context ctx;
    struct mk_list *map;
    struct mk_list properties;
    struct flb_slist_entry *e;
    struct flb_config *config;

    config = flb_config_init();
    if (!config) {
        exit(1);
    }

    memset(&ctx, '\0', sizeof(struct context));
    mk_list_init(&properties);

    map = flb_config_map_create(config, config_map);
    TEST_CHECK(map != NULL);

    /* Populate default values only */
    ret = flb_config_map_set(&properties, map, &ctx);
    TEST_CHECK(ret == 0);

    TEST_CHECK(ctx.boolean == 1);
    TEST_CHECK(ctx.num_int == 123);
    TEST_CHECK(ctx.num_double == 0.12345);
    TEST_CHECK(ctx.size == 2000000);
    TEST_CHECK(ctx.time == 7200);
    TEST_CHECK(strcmp(ctx.string, "test") == 0);
    TEST_CHECK(flb_sds_len(ctx.string) == 4);
    TEST_CHECK(mk_list_size(ctx.list1) == 15);
    TEST_CHECK(mk_list_size(ctx.list2) == 5);

    e = mk_list_entry_last(ctx.list2, struct flb_slist_entry, _head);
    TEST_CHECK(strcmp(e->str, "f   ghi jk l m n  o pqr   stuv xyz") == 0);
    flb_config_map_destroy(map);

    flb_config_exit(config);
}

void test_override_defaults()
{
    int ret;
    struct context ctx;
    struct mk_list *map;
    struct mk_list properties;
    struct flb_slist_entry *e;
    struct flb_config *config;

    config = flb_config_init();
    if (!config) {
        exit(1);
    }

    memset(&ctx, '\0', sizeof(struct context));
    mk_list_init(&properties);

    map = flb_config_map_create(config, config_map);
    TEST_CHECK(map != NULL);

    /* Create a properties list that will override default values */
    flb_kv_item_create(&properties, "boolean", "false");
    flb_kv_item_create(&properties, "num_int", "321");
    flb_kv_item_create(&properties, "num_double", "0.54321");
    flb_kv_item_create(&properties, "string", "no test");
    flb_kv_item_create(&properties, "test_time", "1H");
    flb_kv_item_create(&properties, "test_size", "1M");
    flb_kv_item_create(&properties, "test_clist", "abc, def, ghi ,,,,jkl  ");
    flb_kv_item_create(&properties, "test_slist", "abc def ghi jkl m n o");

    /* Populate default values only */
    ret = flb_config_map_set(&properties, map, &ctx);
    TEST_CHECK(ret == 0);

    TEST_CHECK(ctx.boolean == 0);
    TEST_CHECK(ctx.num_int == 321);
    TEST_CHECK(ctx.num_double == 0.54321);
    TEST_CHECK(ctx.size == 1000000);
    TEST_CHECK(ctx.time == 3600);
    TEST_CHECK(strcmp(ctx.string, "no test") == 0);
    TEST_CHECK(flb_sds_len(ctx.string) == 7);
    TEST_CHECK(mk_list_size(ctx.list1) == 4);
    TEST_CHECK(mk_list_size(ctx.list2) == 5);

    e = mk_list_entry_last(ctx.list2, struct flb_slist_entry, _head);
    TEST_CHECK(strcmp(e->str, "m n o") == 0);

    flb_kv_release(&properties);
    flb_config_map_destroy(map);

    flb_config_exit(config);
}

/* Check that single property raise an error if are set multiple times (dups) */
void test_no_multiple()
{
    int ret;
    struct context ctx;
    struct mk_list *map;
    struct mk_list prop;
    struct flb_config *config;

    config = flb_config_init();
    if (!config) {
        exit(1);
    }

    memset(&ctx, '\0', sizeof(struct context));

    /* Assign the property multiple times */
    flb_kv_init(&prop);
    flb_kv_item_create(&prop, "no_mult", "true");
    flb_kv_item_create(&prop, "no_mult", "false");

    map = flb_config_map_create(config, config_map_mult);
    TEST_CHECK(map != NULL);

    ret = flb_config_map_properties_check("test", &prop, map);
    TEST_CHECK(ret == -1);

    flb_config_map_destroy(map);
    flb_kv_release(&prop);

    flb_config_exit(config);
}

void test_multiple()
{
    int ret;
    int i;
    int total;
    struct context ctx;
    struct mk_list *map;
    struct mk_list prop;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_config *config;

    config = flb_config_init();
    if (!config) {
        exit(1);
    }

    memset(&ctx, '\0', sizeof(struct context));

    /* Create invalid property */
    flb_kv_init(&prop);
    flb_kv_item_create(&prop, "mult_boolean", "true");
    flb_kv_item_create(&prop, "mult_boolean", "false");

    flb_kv_item_create(&prop, "mult_clist", "a, b, c");
    flb_kv_item_create(&prop, "mult_clist", "d, e, f");
    flb_kv_item_create(&prop, "mult_clist", "g, h, i");

    flb_kv_item_create(&prop, "mult_slist", "d e f g");

    map = flb_config_map_create(config, config_map_mult);
    TEST_CHECK(map != NULL);

    ret = flb_config_map_properties_check("test", &prop, map);
    TEST_CHECK(ret == 0);

    ret = flb_config_map_set(&prop, map, &ctx);
    TEST_CHECK(ret == 0);

    i = 0;
    flb_config_map_foreach(head, mv, ctx.mult_boolean) {
        if (i == 0) {
            TEST_CHECK(mv->val.boolean == FLB_TRUE);
        }
        else {
            TEST_CHECK(mv->val.boolean == FLB_FALSE);
        }
        i++;
    }

    total = 0;
    flb_config_map_foreach(head, mv, ctx.mult_list1) {
        total++;
    }
    TEST_CHECK(total == 4);

    total = 0;
    flb_config_map_foreach(head, mv, ctx.mult_list2) {
        total++;
    }

    flb_config_map_destroy(map);
    flb_kv_release(&prop);
    flb_config_exit(config);
}

/* Test that special properties like 'condition' are properly handled */
void test_special_properties()
{
    int ret;
    struct context ctx;
    struct mk_list *map;
    struct mk_list prop;
    struct flb_config *config;

    config = flb_config_init();
    if (!config) {
        exit(1);
    }

    memset(&ctx, '\0', sizeof(struct context));

    /* Create properties with 'condition' and 'active' special properties */
    flb_kv_init(&prop);
    flb_kv_item_create(&prop, "condition", "{\"op\": \"and\", \"rules\": [{\"field\": \"$level\", \"op\": \"eq\", \"value\": \"error\"}]}");
    flb_kv_item_create(&prop, "active", "true");
    
    /* Add a regular property too */
    flb_kv_item_create(&prop, "boolean", "true");

    map = flb_config_map_create(config, config_map);
    TEST_CHECK(map != NULL);

    /* This should succeed despite 'condition' not being in the config_map */
    ret = flb_config_map_properties_check("test", &prop, map);
    TEST_CHECK(ret == 0);

    /* Test that normal properties are still set correctly */
    ret = flb_config_map_set(&prop, map, &ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx.boolean == 1);

    flb_config_map_destroy(map);
    flb_kv_release(&prop);

    flb_config_exit(config);
}

TEST_LIST = {
    { "helper"            , test_helper},
    { "create"            , test_create},
    { "override_defaults" , test_override_defaults},
    { "no_multiple"       , test_no_multiple},
    { "multiple"          , test_multiple},
    { "special_properties", test_special_properties},
    { 0 }
};

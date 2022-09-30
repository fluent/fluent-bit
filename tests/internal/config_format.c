/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>

#include <cfl/cfl.h>
#include <cfl/cfl_variant.h>
#include <cfl/cfl_kvlist.h>

#include "flb_tests_internal.h"

void test_api()
{
	struct flb_cf *cf;
	struct flb_cf_section *s_tmp;
	struct flb_cf_section *service;
	struct flb_cf_group *g_tmp;
	struct cfl_variant *ret;
	struct flb_kv *meta;

	/* create context */
	cf = flb_cf_create();
	TEST_CHECK(cf != NULL);

	/* create service section */
	service = flb_cf_section_create(cf, "SERVICE", 7);
	TEST_CHECK(service != NULL);

	/* add a property */
	ret = flb_cf_section_property_add(cf, service->properties, "key", 3, "val", 3);
	TEST_CHECK(ret != NULL);

	/* add a property with empty spaces on left/right */
	ret = flb_cf_section_property_add(cf, service->properties, " key ", 5, " val   ", 7);
	TEST_CHECK(ret != NULL);

	/* add an invalid property */
	ret = flb_cf_section_property_add(cf, service->properties, "   ", 3, "", 0);
	TEST_CHECK(ret == NULL);

	/* try to add another 'SERVICE' section, it should return the same one */
	s_tmp = flb_cf_section_create(cf, "SERVICE", 7);
	TEST_CHECK(s_tmp == service);

	/* add a valid section */
	s_tmp = flb_cf_section_create(cf, "INPUT", 5);
	TEST_CHECK(s_tmp != NULL);

	TEST_CHECK(mk_list_size(&cf->inputs) == 1);

	/* add property to the section recently created */
	ret = flb_cf_section_property_add(cf, s_tmp->properties, "key", 3, "val", 3);
	TEST_CHECK(ret != NULL);

	/* groups: add groups to the last section created */
	g_tmp = flb_cf_group_create(cf, s_tmp, "FLUENT GROUP", 12);
	TEST_CHECK(g_tmp != NULL);

	/* add properties to the group */
	ret = flb_cf_section_property_add(cf, g_tmp->properties, "key", 3, "val", 3);
	TEST_CHECK(ret != NULL);

	/* groups: invalid group */
	g_tmp = flb_cf_group_create(cf, s_tmp, "", 0);
	TEST_CHECK(g_tmp == NULL);

	/* Meta commands */
	meta = flb_cf_meta_property_add(cf, "@SET        a=1     ", 20);
        TEST_CHECK(meta != NULL);
        TEST_CHECK(flb_sds_len(meta->key) == 3 && strcmp(meta->key, "SET") == 0);
        TEST_CHECK(flb_sds_len(meta->val) == 3 && strcmp(meta->val, "a=1") == 0);

	/* invalid meta */
	meta = flb_cf_meta_property_add(cf, "@a=1 ", 5);
	TEST_CHECK(meta == NULL);

	/* destroy context */
	flb_cf_destroy(cf);
}

TEST_LIST = {
    { "api"    , test_api},
    { 0 }
};

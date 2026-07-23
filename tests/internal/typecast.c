/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_typecast.h>
#include "flb_tests_internal.h"
#include <msgpack.h>
#include <string.h>

void str_to_int()
{
    char *input = "1234";
        
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t off = 0;

    struct flb_typecast_rule *rule = NULL;
    struct flb_typecast_value *val = NULL;

    /* create input object */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_str(&pck, strlen(input));
    msgpack_pack_str_body(&pck, input, strlen(input));

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);

    /* create rule */
    rule = flb_typecast_rule_create("string", 6, "int", 3);
    if (!TEST_CHECK(rule != NULL)) {
        TEST_MSG("failed to create rule");
        exit(EXIT_FAILURE);
    }

    val = flb_typecast_value_create(result.data, rule);
    if(!TEST_CHECK(val != NULL)){
        TEST_MSG("failed to create value");
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(val->type == FLB_TYPECAST_TYPE_INT);
    if(!TEST_CHECK(val->val.i_num == 1234)) {
        TEST_MSG("got %ld. expect 1234", val->val.i_num);
    }

    flb_typecast_rule_destroy(rule);
    flb_typecast_value_destroy(val);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&result);
}

void int_to_str()
{
    int input = 1234;
        
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t off = 0;

    struct flb_typecast_rule *rule = NULL;
    struct flb_typecast_value *val = NULL;

    /* create input object */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_int64(&pck, input);

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);

    /* create rule */
    rule = flb_typecast_rule_create("int", 3, "string", 6);
    if (!TEST_CHECK(rule != NULL)) {
        TEST_MSG("failed to create rule");
        exit(EXIT_FAILURE);
    }

    val = flb_typecast_value_create(result.data, rule);
    if(!TEST_CHECK(val != NULL)){
        TEST_MSG("failed to create value");
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(val->type == FLB_TYPECAST_TYPE_STR);
    if(!TEST_CHECK(!strcmp(val->val.str, "1234"))) {
        TEST_MSG("got %s. expect \"1234\"", val->val.str);
    }

    flb_typecast_rule_destroy(rule);
    flb_typecast_value_destroy(val);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&result);
}

void bool_to_str()
{
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t off = 0;

    struct flb_typecast_rule *rule = NULL;
    struct flb_typecast_value *val = NULL;

    /* create input object */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_true(&pck);

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);

    /* create rule */
    rule = flb_typecast_rule_create("bool", 4, "string", 6);
    if (!TEST_CHECK(rule != NULL)) {
        TEST_MSG("failed to create rule");
        exit(EXIT_FAILURE);
    }

    val = flb_typecast_value_create(result.data, rule);
    if(!TEST_CHECK(val != NULL)){
        TEST_MSG("failed to create value");
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(val->type == FLB_TYPECAST_TYPE_STR);
    if(!TEST_CHECK(!strcmp(val->val.str, "true"))) {
        TEST_MSG("got %s. expect \"true\"", val->val.str);
    }

    flb_typecast_rule_destroy(rule);
    flb_typecast_value_destroy(val);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&result);
}

void str_to_bool()
{
    char *input = "true";
        
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t off = 0;

    struct flb_typecast_rule *rule = NULL;
    struct flb_typecast_value *val = NULL;

    /* create input object */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_str(&pck, strlen(input));
    msgpack_pack_str_body(&pck, input, strlen(input));

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);

    /* create rule */
    rule = flb_typecast_rule_create("string", 6, "bool", 4);
    if (!TEST_CHECK(rule != NULL)) {
        TEST_MSG("failed to create rule");
        exit(EXIT_FAILURE);
    }

    val = flb_typecast_value_create(result.data, rule);
    if(!TEST_CHECK(val != NULL)){
        TEST_MSG("failed to create value");
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(val->type == FLB_TYPECAST_TYPE_BOOL);
    if(!TEST_CHECK(val->val.boolean == FLB_TRUE)) {
        TEST_MSG("got %d. expect FLB_TRUE", val->val.boolean);
    }

    flb_typecast_rule_destroy(rule);
    flb_typecast_value_destroy(val);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&result);
}

void str_to_hex()
{
    char *input = "0xdeadbeef";
        
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t off = 0;

    struct flb_typecast_rule *rule = NULL;
    struct flb_typecast_value *val = NULL;

    /* create input object */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_str(&pck, strlen(input));
    msgpack_pack_str_body(&pck, input, strlen(input));

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);

    /* create rule */
    rule = flb_typecast_rule_create("string", 6, "hex", 3);
    if (!TEST_CHECK(rule != NULL)) {
        TEST_MSG("failed to create rule");
        exit(EXIT_FAILURE);
    }

    val = flb_typecast_value_create(result.data, rule);
    if(!TEST_CHECK(val != NULL)){
        TEST_MSG("failed to create value");
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(val->type == FLB_TYPECAST_TYPE_HEX);
    if(!TEST_CHECK(val->val.ui_num == 0xdeadbeef)) {
        TEST_MSG("got 0x%lx. expect 0xdeadbeef", val->val.ui_num);
    }

    flb_typecast_rule_destroy(rule);
    flb_typecast_value_destroy(val);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&result);
}

void str_to_float()
{
    char *input = "1234.567";
        
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t off = 0;

    struct flb_typecast_rule *rule = NULL;
    struct flb_typecast_value *val = NULL;

    /* create input object */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_str(&pck, strlen(input));
    msgpack_pack_str_body(&pck, input, strlen(input));

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);

    /* create rule */
    rule = flb_typecast_rule_create("string", 6, "float", 5);
    if (!TEST_CHECK(rule != NULL)) {
        TEST_MSG("failed to create rule");
        exit(EXIT_FAILURE);
    }

    val = flb_typecast_value_create(result.data, rule);
    if(!TEST_CHECK(val != NULL)){
        TEST_MSG("failed to create value");
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(val->type == FLB_TYPECAST_TYPE_FLOAT);
    if(!TEST_CHECK(val->val.d_num == 1234.567)) {
        TEST_MSG("got %f. expect 1234.567", val->val.d_num);
    }

    flb_typecast_rule_destroy(rule);
    flb_typecast_value_destroy(val);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&result);
}

void float_to_str()
{
    double input = 1234.567;
        
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t off = 0;

    struct flb_typecast_rule *rule = NULL;
    struct flb_typecast_value *val = NULL;

    /* create input object */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_float(&pck, input);

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);

    /* create rule */
    rule = flb_typecast_rule_create("float", 5, "string", 6);
    if (!TEST_CHECK(rule != NULL)) {
        TEST_MSG("failed to create rule");
        exit(EXIT_FAILURE);
    }

    val = flb_typecast_value_create(result.data, rule);
    if(!TEST_CHECK(val != NULL)){
        TEST_MSG("failed to create value");
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(val->type == FLB_TYPECAST_TYPE_STR);
    if(!TEST_CHECK(strstr(val->val.str, "1234.567") != NULL)) {
        TEST_MSG("got %s. expect \"1234.567\"", val->val.str);
    }

    flb_typecast_rule_destroy(rule);
    flb_typecast_value_destroy(val);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&result);
}

void map_to_json_str()
{
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t off = 0;

    struct flb_typecast_rule *rule = NULL;
    struct flb_typecast_value *val = NULL;

    /* create input object */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    /* map {"k":"v"}*/
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "k", 1);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "v", 1);

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);

    /* create rule */
    rule = flb_typecast_rule_create("map", 3, "json_string", 11);
    if (!TEST_CHECK(rule != NULL)) {
        TEST_MSG("failed to create rule");
        exit(EXIT_FAILURE);
    }

    val = flb_typecast_value_create(result.data, rule);
    if(!TEST_CHECK(val != NULL)){
        TEST_MSG("failed to create value");
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(val->type == FLB_TYPECAST_TYPE_JSON_STR);
    if(!TEST_CHECK(strstr(val->val.str, "\"k\":\"v\"") != NULL)) {
        TEST_MSG("got %s. expect \"k\":\"v\"", val->val.str);
    }

    flb_typecast_rule_destroy(rule);
    flb_typecast_value_destroy(val);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&result);
}

TEST_LIST = {
    {"str_to_int",     str_to_int},
    {"int_to_str",     int_to_str},
    {"str_to_float",   str_to_float},
    {"float_to_str",   float_to_str},
    {"bool_to_str",    bool_to_str},
    {"str_to_bool",    str_to_bool},
    {"str_to_hex",     str_to_hex},
    {"map_to_json_str",map_to_json_str},
    {NULL, NULL}
};

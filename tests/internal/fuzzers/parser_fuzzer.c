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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_parser_decoder.h>

#include "flb_fuzz_header.h"

#define TYPES_LEN 5

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    TIMEOUT_GUARD

    char *format      = NULL;
    char *time_fmt    = NULL;
    char *time_key    = NULL;
    char *time_offset = NULL;
    char *pregex      = NULL;
    struct flb_parser_types *types = NULL;
    struct flb_config *fuzz_config = NULL;
    struct flb_parser *fuzz_parser = NULL;
    int time_keep = 0;
    int types_len = 0;

    /* Set fuzzer-malloc chance of failure */
    flb_malloc_mod = 25000;
    flb_malloc_p = 0;

    if (size < 100) {
        return 0;
    }

    /* json parser */
    fuzz_config = flb_config_init();

    /* format + pregex */
    if (GET_MOD_EQ(4,0)) {
        format = "json";
    }
    else if (GET_MOD_EQ(4,1)) {
        format = "regex";
#ifdef PREG_FUZZ
        pregex = malloc(30);
        pregex[29] = '\0';
        memcpy(pregex, data, 29);
        data += 29;
        size -= 29;
#else
        pregex = "^(?<INT>[^ ]+) (?<FLOAT>[^ ]+) (?<BOOL>[^ ]+) (?<STRING>.+)$";
#endif
    }
    else if (GET_MOD_EQ(4,2)) {
        format = "ltsv";
    }
    else {
        format = "logfmt";
    }
    MOVE_INPUT(1);

    /* time_fmt */
    if (GET_MOD_EQ(2,1)) {
        time_fmt = get_null_terminated(15, &data, &size);
    }
    MOVE_INPUT(1);

    /* time_key */
    if (GET_MOD_EQ(2,1)) {
        time_key = get_null_terminated(15, &data, &size);
    }
    MOVE_INPUT(1);

    /* time_offset */
    if (GET_MOD_EQ(2,1)) {
        time_offset = get_null_terminated(15, &data, &size);
    }
    MOVE_INPUT(1);

    /* time_keep */
    time_keep = (GET_MOD_EQ(2,1)) ? MK_TRUE : MK_FALSE;
    MOVE_INPUT(1);

    /* types_str */
    if (GET_MOD_EQ(2,1)) {
        types =  flb_malloc(sizeof(struct flb_parser_types) * TYPES_LEN);
        char *parser_type_keys[5] = {"AAA", "BBB", "CCC", "DDD", "EEE" };
        int parser_types[5] = {FLB_PARSER_TYPE_INT, FLB_PARSER_TYPE_FLOAT,
                               FLB_PARSER_TYPE_BOOL, FLB_PARSER_TYPE_STRING,
                               FLB_PARSER_TYPE_HEX};
        for (int i = 0; i < TYPES_LEN; i++) {
            types[i].key     = strdup(parser_type_keys[i]);
            types[i].key_len = strlen(parser_type_keys[i]);
            types[i].type    = parser_types[i];
        }
        types_len = TYPES_LEN;
    }
    MOVE_INPUT(1);

    /* decoders */
    struct mk_list *list = NULL;
    if (GET_MOD_EQ(2,1)) {
        MOVE_INPUT(1);
        list = flb_malloc(sizeof(struct mk_list));
        mk_list_init(list);

        struct flb_parser_dec *dec = malloc(sizeof(struct flb_parser_dec));
        dec->key            = flb_sds_create_len("AAA", 3);
        dec->buffer         = flb_sds_create_size(FLB_PARSER_DEC_BUF_SIZE);
        dec->add_extra_keys = FLB_TRUE;
        mk_list_init(&dec->rules);
        mk_list_add(&dec->_head, list);

        struct flb_parser_dec_rule *dec_rule = malloc(sizeof(struct flb_parser_dec_rule));
        dec_rule->type = (int)(data[0] % 0x02);
        MOVE_INPUT(1);
        dec_rule->backend = (int)(data[0] % 0x04);
        MOVE_INPUT(1);
        dec_rule->action = (int)data[0] % 0x03;
        mk_list_add(&dec_rule->_head, &dec->rules);

        if (GET_MOD_EQ(2,1)) {
            struct flb_parser_dec_rule *dec_rule2 = malloc(sizeof(struct flb_parser_dec_rule));
            dec_rule2->type = (int)(data[0] % 0x02);
            MOVE_INPUT(1);
            dec_rule2->backend = (int)(data[0] % 0x04);
            MOVE_INPUT(1);
            dec_rule->action = (int)data[0] % 0x03;
            mk_list_add(&dec_rule2->_head, &dec->rules);
        }
    }
    MOVE_INPUT(1);
    /* print our config struct */
    flb_utils_print_setup(fuzz_config);

    /* now call into the parser */
    fuzz_parser = flb_parser_create("fuzzer", format, pregex, FLB_TRUE,
            time_fmt, time_key, time_offset, time_keep, 0, FLB_FALSE,
            types, types_len, list, fuzz_config);

    /* Second step is to use the random parser to parse random input */
    if (fuzz_parser != NULL) {
        void *out_buf = NULL;
        size_t out_size = 0;
        struct flb_time out_time;
        flb_parser_do(fuzz_parser, (char*)data, size,
                      &out_buf, &out_size, &out_time);
        if (out_buf != NULL) {
            free(out_buf);
        }
        flb_parser_destroy(fuzz_parser);
    }
    else {
        /* Parser creation failed but we still need to clean
         * up types and decoders */
        if (types != NULL) {
            for (int i=0; i< TYPES_LEN; i++){
                flb_free(types[i].key);
            }
            flb_free(types);
        }
        if (list != NULL) {
            flb_parser_decoder_list_destroy(list);
        }
    }

    /* Cleanup everything but the parser */
    flb_config_exit(fuzz_config);
    if (time_fmt != NULL) {
      flb_free(time_fmt);
    }
    if (time_key != NULL) {
        flb_free(time_key);
    }
    if (time_offset != NULL) {
        flb_free(time_offset);
    }
#ifdef PREG_FUZZ
    if (pregex != NULL) {
        flb_free(pregex);
    }
#endif

    return 0;
}

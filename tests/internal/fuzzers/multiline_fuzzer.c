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
#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>
#include <fluent-bit/multiline/flb_ml_rule.h>

#include "flb_fuzz_header.h"

static int flush_callback(struct flb_ml_parser *parser,
                          struct flb_ml_stream *mst, void *data, char *buf_data,
                          size_t buf_size) {
  return 0;
}

struct record_check {
    char *buf;
};

struct expected_result {
    int current_record;
    char *key;
    struct record_check *out_records;
};

int test_multiline_parser(msgpack_object *root2, char *str1, size_t str1_len) {
    uint64_t stream_id;
    struct expected_result res = {0};
    struct flb_config *config = NULL;

    config = flb_config_init();

    struct flb_ml *ml = NULL;
    ml = flb_ml_create(config, "fuzz-test");

    if (ml != NULL) {
        struct flb_ml_parser_ins *mlp_i = NULL;
        mlp_i = flb_ml_parser_instance_create(ml, "docker");

        if (mlp_i != NULL) {
            flb_ml_stream_create(ml, "java", -1, flush_callback, (void *)&res,
                                 &stream_id);

            /* Target with msgpack object */
            struct flb_time tm;
            flb_time_get(&tm);
            flb_ml_append_object(ml, stream_id, &tm, root2);

            /* Target with raw text */
            struct flb_time tm2;
            flb_time_get(&tm2);
            flb_ml_append(ml, stream_id, FLB_ML_TYPE_TEXT, &tm2, str1, str1_len);
        }
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

int LLVMFuzzerTestOneInput(unsigned char *data, size_t size) {
		TIMEOUT_GUARD

    if (size < 50) {
        return 0;
    }

    char *raw_data_to_parse = get_null_terminated(40, &data, &size);

    char *out_buf = NULL;
    size_t out_size;
    int root_type;
    int ret = flb_pack_json((char *)data, size, &out_buf, &out_size, &root_type);
    if (ret == 0) {
        size_t off = 0;
        msgpack_unpacked result;
        msgpack_unpacked_init(&result);
        int ret2 = msgpack_unpack_next(&result, out_buf, out_size, &off);
        if (ret2 == MSGPACK_UNPACK_SUCCESS) {
            msgpack_object root = result.data;

            /* Pass fuzz data into the multiline parser code */
            test_multiline_parser(&root, raw_data_to_parse, 40);
        }
        msgpack_unpacked_destroy(&result);
        free(out_buf);
    }
    free(raw_data_to_parse);
}

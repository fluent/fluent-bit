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

char *random_strings[4];

void test_multiline_parser(msgpack_object *root2, int rand_val) {
    struct expected_result res = {0};
    struct flb_config *config = NULL;

    config = flb_config_init();

    struct flb_ml *ml = NULL;
    ml = flb_ml_create(config, "fuzz-test");

    if (ml != NULL) {
        uint64_t stream_ids[5];

        flb_ml_parser_instance_create(ml, "docker");
        flb_ml_parser_instance_create(ml, "python");
        flb_ml_parser_instance_create(ml, "go");
        flb_ml_parser_instance_create(ml, "cri");
        struct flb_ml_parser_ins *mlp_i =
            flb_ml_parser_instance_create(ml, "java");
        flb_ml_parser_instance_set(mlp_i, "key_content", "log");

        if (rand_val & 0x01) {
            flb_ml_stream_create(ml, "java", -1, flush_callback, (void *)&res,
                                 &(stream_ids[0]));
        }
        if (rand_val >> 1 & 0x01) {
            flb_ml_stream_create(ml, "python", -1, flush_callback, (void *)&res,
                                 &(stream_ids[1]));
        }
        if (rand_val >> 2 & 0x01) {
            flb_ml_stream_create(ml, "go", -1, flush_callback, (void *)&res,
                                 &(stream_ids[2]));
        }
        if (rand_val >> 3 & 0x01) {
            flb_ml_stream_create(ml, "docker", -1, flush_callback, (void *)&res,
                                 &(stream_ids[3]));
        }
        if (rand_val >> 4 & 0x01) {
            flb_ml_stream_create(ml, "cri", -1, flush_callback, (void *)&res,
                                 &(stream_ids[4]));
        }

        /* Target with msgpack object */
        if (root2 != NULL) {
            struct flb_time tm;
            flb_time_get(&tm);
            for (int i = 0; i < 4; i++) {
                flb_ml_append_object(ml, stream_ids[i], &tm, NULL, root2);
            }
        }

        /* Target with raw text */
        struct flb_time tm2;
        flb_time_get(&tm2);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 5; j++) {
                if (random_strings[i] != NULL && stream_ids[j] != NULL) {
                    /* stream_ids index by j, random_strings index by i */
                    flb_ml_append_text(ml, stream_ids[j], &tm2,
                                       random_strings[i], strlen(random_strings[i]));
                    flb_ml_append_text(ml, stream_ids[j], &tm2,
                                       random_strings[i], strlen(random_strings[i]));
                    flb_ml_append_text(ml, stream_ids[j], &tm2,
                                       random_strings[i], strlen(random_strings[i]));
                    flb_ml_append_text(ml, stream_ids[j], &tm2,
                                       random_strings[i],strlen(random_strings[i]));
                    flb_ml_append_text(ml, stream_ids[j], &tm2,
                                       random_strings[i], strlen(random_strings[i]));
                }
            }
        }
    }

    flb_ml_flush_pending_now(ml);

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIMEOUT_GUARD
    /* Set fuzzer-malloc chance of failure */
    flb_malloc_mod = 25000;
    flb_malloc_p = 0;
    /* Ensure there's enough data */
    if (size < 250) {
        return 0;
    }

    int rand_val = *(int *)data;
    data += 4;
    size -= 4;
    for (int i = 0; i < 4; i++) {
        random_strings[i] = NULL;
    }

    random_strings[0] = get_null_terminated(40, &data, &size);
    random_strings[1] = get_null_terminated(40, &data, &size);
    random_strings[2] = get_null_terminated(40, &data, &size);
    random_strings[3] = get_null_terminated(40, &data, &size);

    char *out_buf = NULL;
    size_t out_size;
    int root_type;
    int ret =
        flb_pack_json((char *)data, size, &out_buf, &out_size, &root_type, NULL);
    if (ret == 0) {
        size_t off = 0;
        msgpack_unpacked result;
        msgpack_unpacked_init(&result);
        int ret2 = msgpack_unpack_next(&result, out_buf, out_size, &off);
        if (ret2 == MSGPACK_UNPACK_SUCCESS) {
            msgpack_object root = result.data;

            /* Pass fuzz data into the multiline parser code */
            test_multiline_parser(&root, rand_val);
        }
        msgpack_unpacked_destroy(&result);
        free(out_buf);
    } else {
        test_multiline_parser(NULL, rand_val);
    }

    for (int i = 0; i < 4; i++) {
        if (random_strings[i] != NULL) {
            free(random_strings[i]);
        }
    }
    return 0;
}

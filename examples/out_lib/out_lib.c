/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_compat.h>
#include <msgpack.h>

int my_stdout_json(void *record, size_t size, void *data)
{
    printf("[%s]",__FUNCTION__);
    printf("%s",(char*)record);
    printf("\n");

    flb_lib_free(record);
    return 0;
}

int my_stdout_msgpack(void *record, size_t size, void *data)
{
    printf("[%s]",__FUNCTION__);

    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    struct flb_time tmp_time;
    msgpack_object *x;

    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        printf("[%zd]: [", cnt++);
        flb_time_pop_from_msgpack(&tmp_time, &result, &x);
        printf("%"PRIu32".%09lu, ", (uint32_t)tmp_time.tm.tv_sec, tmp_time.tm.tv_nsec);

        if(x->type == MSGPACK_OBJECT_MAP){
            fprintf(stdout, "{");
            if(x->via.map.size != 0) {
                msgpack_object_kv* p = x->via.map.ptr;
                msgpack_object_kv* const pend = x->via.map.ptr + x->via.map.size;
                do{
                    if (p->key.type != MSGPACK_OBJECT_STR || p->val.type != MSGPACK_OBJECT_STR){
                        break;
                    }
                    msgpack_object_print(stdout, p->key);
                    fprintf(stdout, "=>");
                    msgpack_object_print(stdout, p->val);
                    ++p;
                } while(p < pend);
            }
            fprintf(stdout, "}");
        }

        printf("]\n");
    }
    msgpack_unpacked_destroy(&result);

    flb_lib_free(record);
    return 0;
}

int main()
{
    int i;
    int n;
    char tmp[256];
    flb_ctx_t *ctx;
    struct flb_lib_out_cb callback_json;
    struct flb_lib_out_cb callback_msgpack;
    int in_ffd;
    int out_ffd, out_ffd_msgpack;

    /* Initialize library */
    ctx = flb_create();
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    in_ffd = flb_input(ctx, "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Register output callback functions */

    /* JSON format */
    callback_json.cb = my_stdout_json;
    callback_json.data = NULL;

    out_ffd = flb_output(ctx, "lib", &callback_json);
    flb_output_set(ctx, out_ffd, "match", "test", "format", "json", NULL);

    /* Msgpack format */
    callback_msgpack.cb = my_stdout_msgpack;
    callback_msgpack.data = NULL;
    out_ffd_msgpack = flb_output(ctx, "lib", &callback_msgpack);
    flb_output_set(ctx, out_ffd_msgpack, "match", "test", NULL);

    /* Start the background worker */
    flb_start(ctx);

    /* Push some data every 1s */
    for (i = 0; i < 10; i++) {
        n = snprintf(tmp, sizeof(tmp) - 1,
                     "[%f, {\"key\": \"val %i\"}]",
                     flb_time_now(), i);
        flb_lib_push(ctx, in_ffd, tmp, n);
        usleep(1000000);
    }

    fflush(stdout);

    flb_stop(ctx);

    /* Release Resources */
    flb_destroy(ctx);

    return 0;
}

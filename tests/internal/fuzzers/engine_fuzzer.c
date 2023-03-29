#include <fluent-bit.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_metrics.h>
#include "flb_fuzz_header.h"

#include <stdio.h>
#include <monkey/mk_core.h>

struct flb_parser *parser;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
int filter_ffd;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 100) {
        return 0;
    }
    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;

    uint8_t ud = data[0];
    MOVE_INPUT(1);
    #define NM_SIZE 50
    char *null_terminated = get_null_terminated(NM_SIZE, &data, &size);

    char *nm3 = get_null_terminated(10, &data, &size);
    char *nm4 = get_null_terminated(10, &data, &size);
    int random_i1 = *(int *)data;
    MOVE_INPUT(4);
    int random_i2 = *(int *)data;

	#define FUNC_NUMS 10
    switch (ud % FUNC_NUMS) {
        case 0:
            flb_output(ctx, null_terminated, nm3);
            break;
        case 1:
            flb_filter(ctx, null_terminated, nm3);
            break;
        case 2:
            flb_input(ctx, null_terminated, nm3);
            break;
        case 3:
            flb_output_check(ctx->config);
            break;
        case 4: {
                struct mk_list *head;
                struct flb_input_instance *entry;
                mk_list_foreach(head, &ctx->config->inputs) {
                    entry = mk_list_entry(head, struct flb_input_instance, _head);
                    flb_input_name_exists(nm3, ctx->config);
                    flb_input_get_property(nm3, entry);
                    flb_input_name(entry);
                    flb_input_collector_running(0, entry);
                    flb_input_collector_pause(random_i1, entry);
                    flb_input_collector_resume(random_i2, entry);
                    flb_input_net_default_listener(nm4, random_i1, entry);
                    flb_input_collector_start(random_i2, entry);
                }
            }
            break;
        case 5: {
                struct mk_list *head;
                struct flb_input_instance *entry;
                mk_list_foreach(head, &ctx->config->inputs) {
                    entry = mk_list_entry(head, struct flb_input_instance, _head);
                    if (entry->storage != NULL) {
                        char bufbuf[100];
                        flb_input_chunk_append_raw(entry, FLB_INPUT_LOGS, 0, "A",
                                                   1, "\0", 0);

                        struct flb_input_chunk *ic = NULL;
                        ic = flb_input_chunk_create(entry, FLB_INPUT_LOGS, nm3, 10);
                        if (ic != NULL) {
                            flb_input_chunk_get_size(ic);
                            flb_input_chunk_set_up_down(ic);
                            flb_input_chunk_down(ic);
                            flb_input_chunk_set_up(ic);
                            flb_input_chunk_get_name(ic);
                            char *tag_buf;
                            int tag_len;
                            flb_input_chunk_get_tag(ic, &tag_buf, &tag_len);
                            size_t flushed;
                            flb_input_chunk_flush(ic, &flushed);
                        }
                    }
                }
            }
            break;
        case 6:
            flb_input_check(ctx->config);
            flb_input_pause_all(ctx->config);
            break;
        case 7: {
                struct mk_list *head;
                struct flb_output_instance *entry;
                mk_list_foreach(head, &ctx->config->outputs) {
                    entry = mk_list_entry(head, struct flb_output_instance, _head);
                    flb_output_net_default(nm4, random_i1, entry);
                    flb_output_name(entry);
                }
            }
            break;
        default:
            flb_lib_push(ctx, in_ffd, null_terminated, NM_SIZE);
            break;
    }

    flb_free(null_terminated);
    flb_free(nm3);
    flb_free(nm4);
    return 0;
}

int callback_test(void* data, size_t size, void* cb_data)
{
    return 0;
}

struct flb_lib_out_cb cb;


int LLVMFuzzerInitialize(int *argc, char ***argv) {
    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0", "Grace",
                    "0", "Log_Level", "debug", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, (char *) "test", NULL);
    flb_input_set(ctx, in_ffd, (char *) "BBBB", NULL);
    flb_input_set(ctx, in_ffd, (char *) "AAAA", NULL);
    flb_input_set(ctx, in_ffd, (char *) "AAAAA", NULL);
    flb_input_set(ctx, in_ffd, (char *) "CC", NULL);
    flb_input_set(ctx, in_ffd, (char *) "A", NULL);

    parser = flb_parser_create("timestamp", "regex", "^(?<time>.*)$", FLB_TRUE,
                                "%s.%L", "time", NULL, MK_FALSE, 0, FLB_FALSE,
                               NULL, 0, NULL, ctx->config);
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    int ret;
    ret = flb_filter_set(ctx, filter_ffd, "Match", "test",
                         "Key_Name", "@timestamp",
                         "Parser", "timestamp",
                         "Reserve_Data", "On",
                         NULL);

    cb.cb   = callback_test;
    cb.data = NULL;
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    flb_output_set(ctx, out_ffd, "Match", "*",
                   "format", "json", NULL);

    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    /* start the engine */
    flb_start(ctx);
}

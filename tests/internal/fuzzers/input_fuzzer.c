#include <fluent-bit.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_time.h>

#include "chunkio/chunkio.h"
#include "flb_fuzz_header.h"


const char *input_chunk_property_keywords[] = {
    "log_suppress_interval",
    "routable",
    "alias",
    "mem_buf_limit",
    "listen",
    "log_level",
    "host",
    "port",
    "ipv6",
    "net.",
    "tls",
    "tls.verify",
    "tls.debug",
    "tls.ca_path",
    "tls.key_file",
    "tls.vhost",
    "tls.ca_file",
    "tls.crt_file",
    "tls.key_passwd",
    "threaded",
    "storage.type",
};

int LLVMFuzzerTestOneInput(const uint8_t *data3, size_t size3)
{
    int i;
    int ret;
    int in_ffd;
    int out_ffd;

    flb_ctx_t *ctx;
    size_t total_bytes;
    struct flb_input_instance *i_ins;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_chunk *ic;
    struct flb_task *task;

    if (size3 < 60) {
        return 0;
    }
    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;
    char *input_buffer1 = get_null_terminated(30, &data3, &size3);
    if (input_buffer1 == NULL) {
        return 0;
    }
    size_t input_buffer1_len = strlen(input_buffer1);

    char *input_buffer2 = get_null_terminated(10, &data3, &size3);
    if (input_buffer2 == NULL) {
        return 0;
    }
    size_t input_buffer_len2 = strlen(input_buffer2);

    char *input_buffer3 = get_null_terminated(10, &data3, &size3);
    if (input_buffer3 == NULL) {
        return 0;
    }
    size_t input_buffer_len3 = strlen(input_buffer3);       
    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();

    /* create chunks in /tmp folder */
    ret = flb_service_set(ctx,
                          "flush", "2", "grace", "1",
                          "storage.path", "/tmp/input-chunk-test/",
                          "Log_Level", "error",
                          NULL);
    if (ret != 0) {
        flb_free(input_buffer1);
        flb_free(input_buffer2); 
        flb_free(input_buffer3);
        return 0;
    }

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    ret = flb_input_set(ctx, in_ffd,
                             "tag", "test",
                             "storage.type", "filesystem",
                             NULL);
    if (ret != 0) {
        flb_free(input_buffer1);
        flb_free(input_buffer2);
        flb_free(input_buffer3);
        return 0;
    }

    /* an invalid output destination */
    out_ffd = flb_output(ctx, (char *) "http", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "Host", "127.0.0.1",
                   "Port", "1",
                   "storage.total_limit_size", "1K",
                   NULL);

    /* Start */
    ret = flb_start(ctx);
    if (ret != 0) {
        flb_free(input_buffer1);
        flb_free(input_buffer2);
        flb_free(input_buffer3);
        return 0;
    }

    i_ins = mk_list_entry_first(&ctx->config->inputs,
                                struct flb_input_instance,
                                _head);

    /* main fuzzing logic */
    flb_input_set_property(i_ins, input_buffer2, input_buffer3);
    for (int i = 0; i < sizeof(input_chunk_property_keywords)/sizeof(char*); i++) {
        flb_input_set_property(i_ins,
                               input_chunk_property_keywords[i],
                               input_buffer3);
    }

    /* Ingest fuzz data sample */ 
    for (i = 0; i < 2; ++i) {
        flb_lib_push(ctx, in_ffd, (char *) input_buffer1, input_buffer1_len);
        sleep(1);
        total_bytes = flb_input_chunk_total_size(i_ins);
        ret = total_bytes > 1000 ? -1 : 0;
    }

    /* FORCE clean up test tasks */
    mk_list_foreach_safe(head, tmp, &i_ins->tasks) {
        task = mk_list_entry(head, struct flb_task, _head);
        flb_info("[task] cleanup test task");
        flb_task_destroy(task, FLB_TRUE);
    }

    /* clean up test chunks */
    mk_list_foreach_safe(head, tmp, &i_ins->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        flb_input_chunk_destroy(ic, FLB_TRUE);
    }
    flb_free(input_buffer1);
    flb_free(input_buffer2);
    flb_free(input_buffer3);

    flb_time_msleep(200);
    flb_stop(ctx);
    flb_destroy(ctx);
}

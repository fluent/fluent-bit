/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test functions */
void flb_test_exit_config_change(void);

/* Test list */
TEST_LIST = {
#ifdef FLB_HAVE_INOTIFY
    {"config_change",   flb_test_exit_config_change },
#endif
    {NULL, NULL}
};

#define WAIT_STOP (1+2) /* grace pause in flb_engine_stop and buffer period */

#ifdef FLB_HAVE_INOTIFY
#include <sys/inotify.h>

void flb_test_exit_config_change(void)
{
    int ret;
    pthread_t tid;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *cdirp;
    char cdir[PATH_MAX];
    char odir[PATH_MAX];

    strcpy(cdir, "/tmp/flb-rt-config_change.XXXXXX");
    cdirp = mkdtemp(cdir);
    TEST_CHECK(cdirp != NULL);

    ctx = flb_create();
    ctx->config->conf_path = strdup(cdir);
    ctx->config->conf_change_fd = inotify_init();
    TEST_CHECK(ctx->config->conf_change_fd > 0);
    ret = inotify_add_watch(ctx->config->conf_change_fd,
                            ctx->config->conf_path,
                            IN_CLOSE_WRITE | IN_CREATE | IN_DELETE |
                            IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF);
    TEST_CHECK(ret == 1);

    flb_service_set(ctx, "Flush", "1",
                         "Log_Level", "info",
                         "Config_Watch", "On",
                         "Grace","1",
                         NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, "foo", 3);
    TEST_CHECK(ret == 3);

    /* If we create a file in config dir, the engine should stop.
       Check that we can write a log message, touch a file, wait,
       check that we cannot write a log message
    */
    sprintf(odir, "%s/foo", cdir);
    ret = open(odir, O_WRONLY |O_CREAT, 0666);
    TEST_CHECK(ret > 0);

    /*
     * Cache the thread-id of the worker. If the code works
     * properly, ctx->config will be destroyed when the engine is
     * stopped, and ctx->config->worker will exit. We will then
     * attempt to send a signal to the config->worker, which
     * should fail since its exited.
     */
    tid = ctx->config->worker;
    sleep(WAIT_STOP);
    TEST_CHECK(pthread_kill(tid, 0) != 0);
    flb_destroy(ctx);
}

#endif


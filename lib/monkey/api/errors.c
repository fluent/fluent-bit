#include <monkey/mk_lib.h>
#include <mk_core/mk_unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define API_ADDR   "127.0.0.1"
#define API_PORT   "2020"

/* Main context set as global so the signal handler can use it */
mk_ctx_t *ctx;

static void signal_handler(int signal)
{
    write(STDERR_FILENO, "[engine] caught signal\n", 23);

    switch (signal) {
    case SIGTERM:
    case SIGINT:
        mk_stop(ctx);
        mk_destroy(ctx);
        _exit(EXIT_SUCCESS);
    default:
        break;
    }
}

static void signal_init()
{
    signal(SIGINT,  &signal_handler);
    signal(SIGTERM, &signal_handler);
}

void cb_ok_200(mk_request_t *request, void *data)
{
    int i = 0;
    (void) data;
    char tmp[32];

    mk_http_status(request, 200);
    mk_http_header(request, "X-Monkey", 8, "OK", 2);

    for (i = 0; i < 100; i++) {
      int len;

      len = snprintf(tmp, sizeof(tmp) - 1, "test %i\n", i);
      mk_http_send(request, tmp, len, NULL);
    }
    mk_http_done(request);
}

void cb_error_404(mk_request_t *request, void *data)
{
    int i = 0;
    (void) data;
    char tmp[32];

    mk_http_status(request, 404);
    mk_http_header(request, "X-Monkey", 8, "OK", 2);

    for (i = 0; i < 100; i++) {
      int len;

      len = snprintf(tmp, sizeof(tmp) - 1, "test %i\n", i);
      mk_http_send(request, tmp, len, NULL);
    }
    mk_http_done(request);
}

int main()
{
    int vid;

    signal_init();

    ctx = mk_create();
    if (!ctx) {
        return -1;
    }

    mk_config_set(ctx,
                  "Listen", API_PORT,
                  NULL);

    vid = mk_vhost_create(ctx, NULL);
    mk_vhost_set(ctx, vid,
                 "Name", "mk_lib",
                 NULL);

    mk_vhost_handler(ctx, vid, "/200", cb_ok_200, NULL);
    mk_vhost_handler(ctx, vid, "/404", cb_error_404, NULL);
    mk_info("Service: http://%s:%s/404",  API_ADDR, API_PORT);
    mk_start(ctx);

    sleep(3600);

    mk_stop(ctx);
    mk_destroy(ctx);


    return 0;
}

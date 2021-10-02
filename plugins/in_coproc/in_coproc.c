#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_utils.h>

#include <signal.h>

#define DEFAULT_BUF_SIZE      4096

struct flb_coproc {
    /* The command to execute */
    const char *cmd;
    /* Keeping track of the process */
    pid_t child_pid;
    flb_pipefd_t child_io[2];
    int collector;
    int restart_count;
    int max_restarts;
    /* Keeping track of the data */
    char *buf;
    size_t buf_size, buf_pos;
    struct flb_parser *parser;
    /* Fluent state */
    struct flb_input_instance *ins;
    bool paused;
};

static int in_coproc_start(struct flb_coproc *ctx, struct flb_config *config);
static int in_coproc_stop(struct flb_coproc *ctx);
static void in_coproc_process_line(struct flb_input_instance *ins, char *buf, int len, struct flb_parser *parser);

/* Read data from the pipe between the processes and trigger restarts if the child process dies */
static int in_coproc_collect(struct flb_input_instance *ins, struct flb_config *config, void *in_context) {
    int len, received, processed;
    char *start, *pos, *end;
    struct flb_coproc *ctx = in_context;

    errno = 0;
    while (FLB_TRUE) {
        received = flb_pipe_r(ctx->child_io[0], ctx->buf + ctx->buf_pos, ctx->buf_size - ctx->buf_pos);
        if (received <= 0) {
            /* If we would block, we're done reading. Exit the loop */
            if (FLB_PIPE_WOULDBLOCK()) {
                break;
            }
            /* If there is still something in the buffer, process it */
            if (ctx->buf_pos != 0) {
                in_coproc_process_line(ins, ctx->buf, ctx->buf_pos, ctx->parser);
                ctx->buf_pos = 0;
            }
            in_coproc_stop(ctx);
            if (!ctx->paused) {
                /* If we're not paused, restart until we've restarted too often */
                if (ctx->restart_count >= ctx->max_restarts) {
                    flb_plg_error(ctx->ins, "coprocess %s restarted too often", ctx->cmd);
                    return -1;
                }
                ctx->restart_count++;
                flb_plg_error(ins, "Restarting coprocess for %s (%d of %d allowed restarts)", ctx->cmd, ctx->restart_count, ctx->max_restarts);
                if(in_coproc_start(ctx, config) < 0) {
                    flb_plg_error(ins, "Unable to start coprocess for %s: %s", ctx->cmd, strerror(errno));
                    return -1;
                }
                flb_input_collector_start(ctx->collector, ins);
            }
            return 0;
        }
        start = ctx->buf;
        end = ctx->buf+received+ctx->buf_pos;
        processed = 0;

        /* One by one read lines from the buffer */
        while (start < end && (pos = memchr(start, '\n', end-start))) {
            len = pos-start;
            in_coproc_process_line(ins, start, len, ctx->parser);
            processed += len + 1;
            start += len + 1;
        }

        /* Done processing, but we keep what we haven't processed yet (incomplete lines) */
        if (processed) {
            memmove(ctx->buf, ctx->buf+processed, received + ctx->buf_pos - processed);
        }
        ctx->buf_pos += (received - processed);
        /* Avoid buffer overruns */
        if(ctx->buf_pos >= ctx->buf_size) {
            flb_plg_error(ins, "Log line exceeds buffer size, dropping start of line");
            ctx->buf_pos = 0;
        }
    }

    return 0;
}

/* Process a single line and add it to the instance's input */
static void in_coproc_process_line(struct flb_input_instance *ins, char *buf, int len, struct flb_parser *parser) {
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;

    flb_time_get(&out_time);
    if (parser) {
        if (flb_parser_do(parser, buf, len, &out_buf, &out_size, &out_time) < 0) {
            flb_plg_trace(ins, "tried to parse '%s'", buf);
            flb_plg_trace(ins, "buf_size %zu", len);
            flb_plg_error(ins, "parser returned an error");
            return;
        }
        if (flb_time_to_double(&out_time) == 0.0) {
            flb_time_get(&out_time);
        }
    }

     msgpack_sbuffer_init(&mp_sbuf);
     msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

     msgpack_pack_array(&mp_pck, 2);
     flb_time_append_to_msgpack(&out_time, &mp_pck, 0);

     if (parser) {
         msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);
         flb_free(out_buf);
     } else {
         msgpack_pack_map(&mp_pck, 1);
         msgpack_pack_str(&mp_pck, 6);
         msgpack_pack_str_body(&mp_pck, "coproc", 6);
         msgpack_pack_str(&mp_pck, len);
         msgpack_pack_str_body(&mp_pck, buf, len);
    }

    flb_input_log_append(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);
}

/* Starts the coprocess and communication with it */
static int in_coproc_start(struct flb_coproc *ctx, struct flb_config *config) {
    pid_t pid;
    int ret;
    int fd;

    if (ctx->child_pid > 0) {
        flb_plg_error(ctx->ins, "child program already running");
        errno = EINVAL;
        return -1;
    }
    flb_plg_info(ctx->ins, "Starting coprocess %s", ctx->cmd);

    ret = flb_pipe_create(ctx->child_io);
    if (ret < 0) {
        flb_pipe_close(ctx->child_io[0]);
        flb_pipe_close(ctx->child_io[1]);
        return -1;
    }
    flb_pipe_set_nonblocking(ctx->child_io[0]);

    ret = flb_input_set_collector_event(ctx->ins, in_coproc_collect, ctx->child_io[0], config);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not set collector for exec input plugin");
        return -1;
    }
    ctx->collector = ret;

    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid > 0) {
        ctx->child_pid = pid;
        flb_pipe_close(ctx->child_io[1]);
        ctx->child_io[1] = -1;
        return 0;
    }
    flb_pipe_close(ctx->child_io[0]);
    dup2(ctx->child_io[1], 1);
    dup2(ctx->child_io[1], 2);
    close(0);
    for (fd = 2; fd < 1024; fd++) {
        if(fd != ctx->child_io[1]) {
             close(fd);
        }
    }
    execl("/bin/sh", "/bin/sh", "-c", ctx->cmd, NULL);
    printf("Failed to start %s: %s", ctx->cmd, strerror(errno));
    exit(97);
}

/* We end communication with the process, then kill it and wait for it to exit */
static int in_coproc_stop(struct flb_coproc *ctx) {
    int stat;
    if (ctx->collector >= 0) {
        flb_input_collector_delete(ctx->collector, ctx->ins);
        ctx->collector = -1;
    }
    if (ctx->child_io[0] > 0) {
        flb_pipe_close(ctx->child_io[0]);
        ctx->child_io[0] = -1;
    }
    if (ctx->child_pid > 0) {
        /* If the child process is still running, kill it */
        if (waitpid(ctx->child_pid, &stat, WNOHANG) <= 0) {
            flb_plg_info(ctx->ins, "Killing process %s, pid %d", ctx->cmd, ctx->child_pid);
            if (kill(ctx->child_pid, SIGINT) < 0) {
                flb_plg_error(ctx->ins, "Unable to kill pid %d: %d", ctx->child_pid, strerror(errno));
            }
        }
        /* Wait for the child process and say something about how it stopped */
        waitpid(ctx->child_pid, &stat, 0);
        if(WIFEXITED(stat)) {
            if(WEXITSTATUS(stat) == 0) {
                flb_plg_info(ctx->ins, "Coprocess %s (pid %d) exited with code %d", ctx->cmd, ctx->child_pid, WEXITSTATUS(stat));
            } else {
                flb_plg_error(ctx->ins, "Coprocess %s (pid %d) exited with code %d", ctx->cmd, ctx->child_pid, WEXITSTATUS(stat));
            }
        } else {
            if (!ctx->paused || WTERMSIG(stat) != SIGINT) {
                flb_plg_error(ctx->ins, "Coprocess %s (pid %d) was terminated by signal %d", ctx->cmd, ctx->child_pid, WTERMSIG(stat));
            }
        }
    }
    ctx->child_pid = 0;
    ctx->child_io[0] = -1;
    ctx->child_io[1] = -1;

    return 0;
}

static int in_coproc_config_read(struct flb_input_instance *in, struct flb_coproc *ctx, struct flb_config *config) {
    const char *parser;

    ctx->ins = in;
    ctx->collector = -1;
    ctx->buf_size = DEFAULT_BUF_SIZE;
    ctx->parser = NULL;
    ctx->buf = NULL;
    ctx->buf_pos = 0;
    ctx->child_io[0] = -1;
    ctx->child_io[1] = -1;
    ctx->max_restarts = INT_MAX;
    ctx->restart_count = 0;
    ctx->paused = FLB_FALSE;

    if (flb_input_config_map_set(in, ctx) == -1) {
        return -1;
    }
    if (ctx->cmd == NULL) {
        flb_plg_error(in, "no command was given");
        return -1;
    }
    if (ctx->buf_size < 0) {
        flb_plg_error(in, "negative buffer size only works in another dimension");
        return -1;
    }

    parser = flb_input_get_property("parser", in);
    if (parser != NULL) {
        ctx->parser = flb_parser_get(parser, config);
        if (ctx->parser == NULL) {
            flb_plg_error(in, "requested parser '%s' not found", parser);
            return -1;
        }
    }

    ctx->buf = flb_malloc(ctx->buf_size);
    if (ctx->buf == NULL) {
        flb_plg_error(in, "could not allocate exec buffer");
        return -1;
    }
    return 0;
}

static int in_coproc_init(struct flb_input_instance *in, struct flb_config *config, void *data) {
    struct flb_coproc *ctx = NULL;

    ctx = flb_malloc(sizeof(struct flb_coproc));
    if (!ctx) {
        return -1;
    }
    if (in_coproc_config_read(in, ctx, config) == -1) {
        goto init_error;
    }

    flb_input_set_context(in, ctx);

    if(in_coproc_start(ctx, config) == -1) {
        flb_plg_error(in, "could not start child process (%d): %s", errno, strerror(errno));
        goto init_error;
    }
    return 0;

init_error:
    flb_free(ctx->buf);
    flb_free(ctx);

    return -1;
}

static int in_coproc_exit(void *data, struct flb_config *config) {
    (void) *config;
    struct flb_coproc *ctx = data;
    in_coproc_stop(ctx);
    flb_free(ctx->buf);
    flb_free(ctx);
    return 0;
}

static void in_coproc_pause(void *data, struct flb_config *config) {
    (void) *config;
    struct flb_coproc *ctx = data;
    ctx->paused = FLB_TRUE;
    in_coproc_stop(ctx);
}

static void in_coproc_resume(void *data, struct flb_config *config) {
    (void) *config;
    struct flb_coproc *ctx = data;
    ctx->paused = FLB_FALSE;
    in_coproc_start(ctx, config);
}

static struct flb_config_map in_coproc_config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "command", NULL,
        0, FLB_TRUE, offsetof(struct flb_coproc, cmd),
        "The name of the command to execute"
    },
    {
        FLB_CONFIG_MAP_STR, "parser", NULL,
        0, FLB_FALSE, 0,
        "The parser to use for the log lines"
    },
    {
        FLB_CONFIG_MAP_SIZE, "buf_size", "4K",
        0, FLB_TRUE, offsetof(struct flb_coproc, buf_size),
        "The size of the input buffer"
    },
    {
        FLB_CONFIG_MAP_INT, "max_restarts", "0",
        0, FLB_TRUE, offsetof(struct flb_coproc, max_restarts),
        "Allow N restarts of the coprocess"
    },
    {0}
};

struct flb_input_plugin in_coproc_plugin = {
    .name        = "coproc",
    .description = "Run a command to collect messages",
    .cb_init     = in_coproc_init,
    .cb_pre_run  = NULL,
    .cb_collect  = in_coproc_collect,
    .cb_exit     = in_coproc_exit,
    .cb_pause    = in_coproc_pause,
    .cb_resume   = in_coproc_resume,
    .config_map  = in_coproc_config_map,
};

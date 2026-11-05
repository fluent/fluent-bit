/* Test-only input owner-thread lifecycle probe. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_scheduler.h>

struct stop_probe {
    char *mode;
    pthread_t owner;
    struct flb_sched_timer *timer;
    struct timespec stopped_at;
    int ticks;
    int stop_ticks;
    int stops;
};

static struct flb_config_map config_map[] = {
    {FLB_CONFIG_MAP_STR, "mode", "normal", 0, FLB_TRUE,
     offsetof(struct stop_probe, mode), "Probe mode"},
    {0}
};

static void tick(struct flb_config *config, void *data)
{
    struct stop_probe *probe;

    (void) config;
    probe = data;
    probe->ticks++;
    if (probe->stops) {
        fprintf(stderr, "stop_probe_bad_tick\n");
    }
}

static int initialize(struct flb_processor_instance *ins, void *source, int type,
                      struct flb_config *config)
{
    struct stop_probe *probe;
    struct flb_processor *parent;

    parent = ins->pu->parent;
    if (parent->source_plugin_type != FLB_PLUGIN_INPUT) {
        return -1;
    }
    (void) source;
    (void) type;
    probe = calloc(1, sizeof(*probe));
    if (probe == NULL) {
        return -1;
    }
    if (flb_config_map_set(config, &ins->properties, ins->config_map, probe) != 0) {
        free(probe);
        return -1;
    }
    probe->owner = pthread_self();
    if (flb_sched_timer_cb_create(flb_sched_ctx_get(), FLB_SCHED_TIMER_CB_PERM,
                                 10, tick, probe, &probe->timer) != 0) {
        free(probe);
        return -1;
    }
    ins->context = probe;
    fprintf(stderr, "stop_probe_init mode=%s\n", probe->mode);
    return strcmp(probe->mode, "fail") == 0 ? -1 : 0;
}

static int stop(struct flb_processor_instance *ins, void *data)
{
    struct stop_probe *probe;

    (void) ins;
    probe = data;
    probe->stops++;
    probe->stop_ticks = probe->ticks;
    clock_gettime(CLOCK_MONOTONIC, &probe->stopped_at);
    if (probe->timer != NULL) {
        flb_sched_timer_invalidate(probe->timer);
        probe->timer = NULL;
    }
    fprintf(stderr, "stop_probe_stop mode=%s count=%d owner=%d\n", probe->mode,
            probe->stops, pthread_equal(pthread_self(), probe->owner));
    return strcmp(probe->mode, "error") == 0 ? -1 : 0;
}

static int process(struct flb_processor_instance *ins, void *data, const char *tag, int length)
{
    struct stop_probe *probe;
    struct timespec now;
    long long elapsed;

    (void) data;
    (void) tag;
    (void) length;
    probe = ins->context;
    if (strcmp(probe->mode, "early") == 0) {
        /* Deliberate repeated stop while the real owner event loop keeps running. */
        flb_processor_input_stop(ins->pu->parent);
        flb_processor_input_stop(ins->pu->parent);
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = (now.tv_sec - probe->stopped_at.tv_sec) * 1000LL +
                  (now.tv_nsec - probe->stopped_at.tv_nsec) / 1000000LL;
        if (elapsed >= 250) {
            fprintf(stderr, "stop_probe_quiet elapsed=%lld stable=%d\n", elapsed,
                    probe->ticks == probe->stop_ticks);
        }
    }
    return 0;
}

static int finish(struct flb_processor_instance *ins, void *data)
{
    struct stop_probe *probe;

    (void) ins;
    probe = data;
    fprintf(stderr, "stop_probe_exit mode=%s stops=%d stable=%d\n", probe->mode,
            probe->stops, probe->ticks == probe->stop_ticks);
    free(probe);
    return 0;
}

struct flb_processor_plugin processor_stop_probe_plugin = {
    .flags = FLB_PROCESSOR_FLAG_INPUT_STOP,
    .name = "stop_probe",
    .description = "Test-only processor input stop lifecycle",
    .config_map = config_map,
    .cb_init = initialize,
    .cb_process_logs = process,
    .cb_exit = finish,
    .cb_input_stop = stop
};

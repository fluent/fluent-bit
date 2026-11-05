/* Test-only lifecycle observer: no production buffering or timer ownership. */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_mp_chunk.h>

struct probe {
    pthread_mutex_t lock;
    pthread_t init_thread;
    pthread_t process_thread;
    int processed;
    int ticks;
    char *held;
    size_t held_size;
    size_t next_stage;
    int released;
    struct flb_config *config;
    struct flb_input_instance *input;
};

static void timer_tick(struct flb_config *config, void *data)
{
    struct probe *probe = data;

    int ret;

    (void) config;
    pthread_mutex_lock(&probe->lock);
    probe->ticks++;
    if (probe->processed) {
        fprintf(stderr, "lifecycle_tick same_process=%d same_init=%d\n",
                pthread_equal(pthread_self(), probe->process_thread),
                pthread_equal(pthread_self(), probe->init_thread));
    }
    if (probe->held && !probe->released) {
        ret = flb_input_log_append_skip_processor_stages(probe->input, probe->next_stage,
                                                         "probe", 5, probe->held, probe->held_size);
        fprintf(stderr, "lifecycle_release status=%d\n", ret);
        if (ret == 0) {
            free(probe->held);
            probe->held = NULL;
            probe->released++;
        }
    }
    pthread_mutex_unlock(&probe->lock);
}

static int initialize(struct flb_processor_instance *ins, void *source, int type,
                      struct flb_config *config)
{
    struct probe *probe;
    struct flb_sched *sched;

    (void) type;
    sched = flb_sched_ctx_get();
    if (!sched) {
        return -1;
    }
    probe = calloc(1, sizeof(*probe));
    if (!probe) {
        return -1;
    }
    pthread_mutex_init(&probe->lock, NULL);
    probe->init_thread = pthread_self();
    probe->input = source;
    probe->next_stage = ins->pu->stage + 1;
    probe->config = config;
    if (flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM, 100,
                                 timer_tick, probe, NULL) != 0) {
        pthread_mutex_destroy(&probe->lock);
        free(probe);
        return -1;
    }
    ins->context = probe;
    return 0;
}

static int process(struct flb_processor_instance *ins, void *data, const char *tag, int length)
{
    struct probe *probe = ins->context;

    struct flb_mp_chunk_cobj *chunk = data;
    struct flb_mp_chunk_record *record;
    struct cfl_list *head;
    struct cfl_list *tmp;

    (void) tag;
    (void) length;
    pthread_mutex_lock(&probe->lock);
    probe->process_thread = pthread_self();
    probe->processed++;
    fprintf(stderr, "lifecycle_processed count=%d\n", probe->processed);
    while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
        /* Materialize the test batch before taking its encoded ownership. */
    }
    if (probe->held || flb_mp_chunk_cobj_encode(chunk, &probe->held, &probe->held_size) != 0) {
        pthread_mutex_unlock(&probe->lock);
        return -1;
    }
    cfl_list_foreach_safe(head, tmp, &chunk->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        flb_mp_chunk_cobj_record_destroy(chunk, record);
    }
    pthread_mutex_unlock(&probe->lock);
    return 0;
}

static int finish(struct flb_processor_instance *ins, void *data)
{
    struct probe *probe = data;

    (void) ins;
    /* Observe the gate without invoking append on already destroyed storage.
     * Schedulers are engine-owned and their loops are stopped before teardown. */
    fprintf(stderr, "lifecycle_exit outputs_empty=%d storage_null=%d processed=%d ticks=%d\n",
            mk_list_is_empty(&probe->config->outputs) == 0, probe->input->storage == NULL,
            probe->processed, probe->ticks);
    fprintf(stderr, "lifecycle_discard held=%d released=%d\n", probe->held != NULL, probe->released);
    free(probe->held);
    pthread_mutex_destroy(&probe->lock);
    free(probe);
    return 0;
}

struct flb_processor_plugin processor_lifecycle_probe_plugin = {
    .name = "lifecycle_probe",
    .description = "Test-only lifecycle observer",
    .cb_init = initialize,
    .cb_process_logs = process,
    .cb_exit = finish
};

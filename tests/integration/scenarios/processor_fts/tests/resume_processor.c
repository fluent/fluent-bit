/* Test-only engine queue ownership/continuation probe. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_mp_chunk.h>

struct resume_probe {
    struct flb_input_instance *input;
    pthread_t owner;
    size_t stage;
    void *pending;
    size_t size;
    int calls;
    int releases;
};

static void tick(struct flb_config *config, void *data)
{
    struct resume_probe *probe;
    int ret;

    (void) config;
    probe = data;
    if (probe->pending == NULL) {
        return;
    }
    ret = flb_input_ingress_try_resume_log(probe->input, probe->stage,
                                          "resume", 6, &probe->pending, probe->size, 1);
    fprintf(stderr, "resume_retry ret=%d cleared=%d owner=%d\n", ret,
            probe->pending == NULL, pthread_equal(pthread_self(), probe->owner));
    if (ret == 0) {
        probe->releases++;
    }
}

static int initialize(struct flb_processor_instance *ins, void *source, int type,
                      struct flb_config *config)
{
    struct resume_probe *probe;

    (void) type;
    (void) config;
    probe = calloc(1, sizeof(*probe));
    if (probe == NULL) {
        return -1;
    }
    probe->input = source;
    probe->owner = pthread_self();
    probe->stage = ins->pu->stage + 1;
    if (flb_input_ingress_enable(probe->input) != 0) {
        free(probe);
        return -1;
    }
    probe->input->ingress_queue_event_limit = 1;
    if (flb_sched_timer_cb_create(flb_sched_ctx_get(), FLB_SCHED_TIMER_CB_PERM,
                                 100, tick, probe, NULL) != 0) {
        free(probe);
        return -1;
    }
    ins->context = probe;
    return 0;
}

static int process(struct flb_processor_instance *ins, void *data, const char *tag, int length)
{
    struct resume_probe *probe;
    struct flb_mp_chunk_cobj *chunk;
    struct flb_mp_chunk_record *record;
    struct cfl_list *head;
    struct cfl_list *tmp;
    char *encoded;
    void *first;
    void *second;
    size_t size;
    int ret;

    (void) tag;
    (void) length;
    probe = ins->context;
    chunk = data;
    probe->calls++;
    if (probe->calls != 1) {
        fprintf(stderr, "resume_reentered\n");
        return -1;
    }
    while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
    }
    if (flb_mp_chunk_cobj_encode(chunk, &encoded, &size) != 0) {
        return -1;
    }
    first = malloc(size);
    second = malloc(size);
    if (first == NULL || second == NULL) {
        free(first);
        free(second);
        free(encoded);
        return -1;
    }
    memcpy(first, encoded, size);
    memcpy(second, encoded, size);
    ret = flb_input_ingress_try_resume_log(probe->input, probe->stage,
                                          "resume", 6, &first, size, 1);
    fprintf(stderr, "resume_first ret=%d cleared=%d\n", ret, first == NULL);
    free(first);
    ret = flb_input_ingress_try_resume_log(probe->input, probe->stage,
                                          "resume", 6, &second, size, 1);
    fprintf(stderr, "resume_second ret=%d intact=%d\n", ret,
            second != NULL && memcmp(second, encoded, size) == 0);
    probe->pending = second;
    probe->size = size;
    free(encoded);
    cfl_list_foreach_safe(head, tmp, &chunk->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        flb_mp_chunk_cobj_record_destroy(chunk, record);
    }
    return 0;
}

static int finish(struct flb_processor_instance *ins, void *data)
{
    struct resume_probe *probe;

    (void) ins;
    probe = data;
    fprintf(stderr, "resume_exit calls=%d releases=%d pending=%d\n",
            probe->calls, probe->releases, probe->pending != NULL);
    /* Loop is stopped; engine owns scheduler cleanup. This probe deliberately
     * does not dereference a timer after the threaded scheduler was destroyed. */
    free(probe->pending);
    free(probe);
    return 0;
}

struct flb_processor_plugin processor_resume_probe_plugin = {
    .name = "resume_probe",
    .description = "Test-only queue ownership and continuation probe",
    .cb_init = initialize,
    .cb_process_logs = process,
    .cb_exit = finish
};

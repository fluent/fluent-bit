/* Test-only ownership probe for pauses before and during ingress draining. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_mp_chunk.h>

struct pause_probe {
    struct flb_input_instance *input;
    struct flb_sched_timer *timer;
    size_t stage;
    int calls;
    int paused;
    int ticks;
};

static void tick(struct flb_config *config, void *data)
{
    struct pause_probe *probe;

    (void) config;
    probe = data;
    if (!probe->paused || ++probe->ticks < 2) {
        return;
    }
    fprintf(stderr, "pause_inventory stage=%zu pending=%zu\n", probe->stage,
            probe->input->ingress_queue_pending_events);
    probe->paused = 0;
    probe->input->mem_buf_status = FLB_INPUT_RUNNING;
    flb_input_plugin_resume(probe->input);
}

static int initialize(struct flb_processor_instance *ins, void *source, int type,
                      struct flb_config *config)
{
    struct pause_probe *probe;

    (void) type;
    (void) config;
    probe = calloc(1, sizeof(*probe));
    if (probe == NULL) {
        return -1;
    }
    probe->input = source;
    probe->stage = ins->pu->stage;
    if (flb_input_ingress_enable(probe->input) != 0) {
        free(probe);
        return -1;
    }
    probe->input->ingress_queue_event_limit = 3;
    probe->input->ingress_queue_byte_limit = 1024 * 1024;
    if (flb_sched_timer_cb_create(flb_sched_ctx_get(), FLB_SCHED_TIMER_CB_PERM,
                                 100, tick, probe, &probe->timer) != 0) {
        free(probe);
        return -1;
    }
    ins->context = probe;
    return 0;
}

static int process(struct flb_processor_instance *ins, void *data, const char *tag, int length)
{
    struct pause_probe *probe;
    struct flb_mp_chunk_cobj *chunk;
    struct flb_mp_chunk_record *record;
    struct cfl_list *head;
    struct cfl_list *tmp;
    char *encoded;
    void *buffer;
    size_t size;
    int i;
    int ret;

    probe = ins->context;
    chunk = data;
    if (probe->stage != 0 && cfl_list_is_empty(&chunk->records)) {
        return 0;
    }
    probe->calls++;
    if (probe->stage == 0) {
        while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
        }
        if (flb_mp_chunk_cobj_encode(chunk, &encoded, &size) != 0) {
            return -1;
        }
        for (i = 0; i < 3; i++) {
            buffer = malloc(size);
            if (buffer == NULL) {
                free(encoded);
                return -1;
            }
            memcpy(buffer, encoded, size);
            ret = flb_input_ingress_try_resume_log(probe->input, 1, tag, length,
                                                  &buffer, size, 1);
            free(buffer);
            if (ret != 0) {
                free(encoded);
                return -1;
            }
        }
        free(encoded);
        cfl_list_foreach_safe(head, tmp, &chunk->records) {
            record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
            flb_mp_chunk_cobj_record_destroy(chunk, record);
        }
    }
    if (probe->calls == 1) {
        probe->paused = 1;
        if (probe->stage == 0) {
            probe->input->mem_buf_status = FLB_INPUT_PAUSED;
            flb_input_plugin_pause(probe->input);
        }
    }
    return 0;
}

static int stop(struct flb_processor_instance *ins, void *data)
{
    struct pause_probe *probe;

    (void) ins;
    probe = data;
    if (probe->timer != NULL) {
        flb_sched_timer_invalidate(probe->timer);
        probe->timer = NULL;
    }
    return 0;
}

static int finish(struct flb_processor_instance *ins, void *data)
{
    struct pause_probe *probe;

    (void) ins;
    probe = data;
    fprintf(stderr, "pause_exit stage=%zu calls=%d\n", probe->stage, probe->calls);
    free(probe);
    return 0;
}

struct flb_processor_plugin processor_pause_probe_plugin = {
    .name = "pause_probe",
    .description = "Test-only deferred-ingestion pause probe",
    .flags = FLB_PROCESSOR_FLAG_INPUT_STOP,
    .cb_init = initialize,
    .cb_process_logs = process,
    .cb_exit = finish,
    .cb_input_stop = stop
};

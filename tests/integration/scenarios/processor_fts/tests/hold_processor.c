/* Test-only bounded holder for core accounting; not an FTS window store. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_log_event_decoder.h>

struct pending {
    void *buffer;
    size_t size;
    size_t records;
    struct pending *next;
};

struct hold_probe {
    struct flb_processor_instance *instance;
    struct flb_input_instance *input;
    struct flb_sched_timer *timer;
    struct pending *head;
    struct pending *tail;
    size_t batches;
    int release;
    int calls;
};

static void tick(struct flb_config *config, void *data)
{
    struct hold_probe *probe;
    struct pending *entry;
    int ret;

    (void) config;
    probe = data;
    while (probe->release && probe->head != NULL) {
        entry = probe->head;
        ret = flb_input_ingress_try_resume_log(probe->input, probe->instance->pu->stage + 1,
                                              "hold", 4, &entry->buffer, entry->size, entry->records);
        if (ret != 0) {
            fprintf(stderr, "hold_probe_retry ret=%d intact=%d inventory=%zu\n", ret,
                    entry->buffer != NULL, probe->instance->log_held_current);
            break;
        }
        ret = flb_processor_log_release(probe->instance, entry->records);
        fprintf(stderr, "hold_probe_release ret=%d records=%zu\n", ret, entry->records);
        probe->head = entry->next;
        probe->batches--;
        free(entry);
    }
    if (probe->head == NULL) {
        probe->tail = NULL;
        probe->release = 0;
    }
}

static int initialize(struct flb_processor_instance *ins, void *source, int type,
                      struct flb_config *config)
{
    struct hold_probe *probe;
    struct flb_processor *parent;

    (void) type;
    (void) config;
    parent = ins->pu->parent;
    if (parent->source_plugin_type != FLB_PLUGIN_INPUT) {
        return -1;
    }
    probe = calloc(1, sizeof(*probe));
    if (probe == NULL) {
        return -1;
    }
    probe->instance = ins;
    probe->input = source;
    if (flb_input_ingress_enable(probe->input) != 0) {
        free(probe);
        return -1;
    }
    probe->input->ingress_queue_event_limit = 1;
    if (flb_sched_timer_cb_create(flb_sched_ctx_get(), FLB_SCHED_TIMER_CB_PERM,
                                 100, tick, probe, &probe->timer) != 0) {
        free(probe);
        return -1;
    }
    ins->context = probe;
    return 0;
}

static int stop(struct flb_processor_instance *ins, void *data)
{
    struct hold_probe *probe;
    struct pending *entry;

    probe = data;
    if (probe->timer != NULL) {
        flb_sched_timer_invalidate(probe->timer);
        probe->timer = NULL;
    }
    while (probe->head != NULL) {
        entry = probe->head;
        probe->head = entry->next;
        flb_processor_log_discard(ins, entry->records);
        free(entry->buffer);
        free(entry);
    }
    probe->tail = NULL;
    probe->batches = 0;
    fprintf(stderr, "hold_probe_stop inventory=%zu\n", ins->log_held_current);
    return 0;
}

static int mixed(struct flb_processor_instance *ins, struct flb_mp_chunk_cobj *chunk)
{
    struct hold_probe *probe;
    struct pending *entry;
    struct flb_mp_chunk_record *first;
    struct flb_mp_chunk_record *second;
    struct flb_mp_chunk_record *third;
    int ret;

    probe = ins->context;
    if (cfl_list_size(&chunk->records) != 3 ||
        flb_mp_chunk_cobj_count_log_records(chunk) != 3 || probe->batches >= 256) {
        return -1;
    }
    entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        return -1;
    }
    first = cfl_list_entry(chunk->records.next, struct flb_mp_chunk_record, _head);
    second = cfl_list_entry(first->_head.next, struct flb_mp_chunk_record, _head);
    third = cfl_list_entry(second->_head.next, struct flb_mp_chunk_record, _head);
    cfl_list_del(&first->_head);
    cfl_list_del(&third->_head);
    chunk->record_pos = NULL;
    ret = flb_mp_chunk_cobj_encode(chunk, (char **) &entry->buffer, &entry->size);
    /* Restore the source order before any potentially failing admission. */
    cfl_list_del(&second->_head);
    cfl_list_add(&first->_head, &chunk->records);
    cfl_list_add(&second->_head, &chunk->records);
    cfl_list_add(&third->_head, &chunk->records);
    if (ret != 0 || flb_processor_log_hold(ins, 1) != 0) {
        free(entry->buffer);
        free(entry);
        return -1;
    }
    entry->records = 1;
    if (probe->tail == NULL) {
        probe->head = entry;
    }
    else {
        probe->tail->next = entry;
    }
    probe->tail = entry;
    probe->batches++;
    flb_mp_chunk_cobj_record_destroy(chunk, second);
    flb_mp_chunk_cobj_record_destroy(chunk, third);
    return 0;
}

static int process(struct flb_processor_instance *ins, void *data, const char *tag, int length)
{
    struct hold_probe *probe;
    struct pending *entry;
    struct flb_mp_chunk_cobj *chunk;
    struct flb_mp_chunk_record *record;
    struct cfl_variant *value;
    struct cfl_list *head;
    struct cfl_list *tmp;
    char action[16];
    size_t action_size;
    int type;
    int records;
    int ret;

    (void) tag;
    (void) length;
    probe = ins->context;
    chunk = data;
    probe->calls++;
    action[0] = '\0';
    while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
        if (action[0] == '\0' && flb_log_event_decoder_get_record_type(&record->event, &type) == 0 &&
            type == FLB_LOG_EVENT_NORMAL && record->cobj_record != NULL &&
            record->cobj_record->variant->type == CFL_VARIANT_KVLIST) {
            value = cfl_kvlist_fetch(record->cobj_record->variant->data.as_kvlist, "action");
            if (value != NULL && value->type == CFL_VARIANT_STRING) {
                action_size = cfl_variant_size_get(value);
                if (action_size < sizeof(action)) {
                    memcpy(action, value->data.as_string, action_size);
                    action[action_size] = '\0';
                }
            }
        }
    }
    if (action[0] == '\0' || strcmp(action, "keep") == 0) {
        return 0;
    }
    records = flb_mp_chunk_cobj_count_log_records(chunk);
    if (strcmp(action, "mixed") == 0) {
        return mixed(ins, chunk);
    }
    if (strcmp(action, "hold") == 0) {
        if (probe->batches >= 256) {
            return -1;
        }
        entry = calloc(1, sizeof(*entry));
        if (entry == NULL) {
            return -1;
        }
        if (flb_mp_chunk_cobj_encode(chunk, (char **) &entry->buffer, &entry->size) != 0) {
            free(entry);
            return -1;
        }
        entry->records = records;
        ret = flb_processor_log_hold(ins, records);
        if (ret != 0) {
            free(entry->buffer);
            free(entry);
            return -1;
        }
        if (probe->tail == NULL) {
            probe->head = entry;
        }
        else {
            probe->tail->next = entry;
        }
        probe->tail = entry;
        probe->batches++;
    }
    else if (strcmp(action, "release") == 0) {
        probe->release = 1;
    }
    else if (strcmp(action, "underflow") == 0) {
        fprintf(stderr, "hold_probe_underflow release=%d\n",
                flb_processor_log_release(ins, ins->log_held_current + 1));
        fprintf(stderr, "hold_probe_underflow discard=%d\n",
                flb_processor_log_discard(ins, ins->log_held_current + 1));
    }
    else if (strcmp(action, "stop") == 0) {
        flb_processor_input_stop(ins->pu->parent);
    }
    cfl_list_foreach_safe(head, tmp, &chunk->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        flb_mp_chunk_cobj_record_destroy(chunk, record);
    }
    return 0;
}

static int finish(struct flb_processor_instance *ins, void *data)
{
    struct hold_probe *probe;

    probe = data;
    fprintf(stderr, "hold_probe_exit inventory=%zu calls=%d\n", ins->log_held_current, probe->calls);
    free(probe);
    return 0;
}

struct flb_processor_plugin processor_hold_probe_plugin = {
    .flags = FLB_PROCESSOR_FLAG_INPUT_STOP
#ifdef PROBE_WINDOWS
        | FLB_PROCESSOR_FLAG_LOG_WINDOWS
#endif
        ,
    .name = "hold_probe",
    .description = "Test-only core HOLD accounting",
    .cb_init = initialize,
    .cb_process_logs = process,
    .cb_input_stop = stop,
    .cb_exit = finish
};

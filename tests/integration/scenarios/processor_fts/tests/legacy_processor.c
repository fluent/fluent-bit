/* Frozen pre-preflight ABI fixture. Do not add the new tail fields here. */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_config.h>

struct legacy_instance {
    int id;
    int log_level;
    int event_type;
    int logs_raw_enabled;
    char name[32];
    char *alias;
    void *context;
    void *data;
    struct flb_processor_unit *pu;
    struct flb_processor_plugin *p;
    struct mk_list properties;
    struct mk_list *config_map;
    struct flb_log_event_decoder *log_decoder;
    struct flb_log_event_encoder *log_encoder;
    struct cmt *cmt;
    flb_pipefd_t notification_channel;
    struct flb_config *config;
};

struct legacy_plugin {
    int flags;
    char *name;
    char *description;
    struct flb_config_map *config_map;
    int (*cb_init)(struct legacy_instance *, void *, int, struct flb_config *);
    int (*cb_process_logs)(struct legacy_instance *, void *, const char *, int);
    int (*cb_process_logs_raw)(struct legacy_instance **, size_t, const void *, size_t,
                              void **, size_t *, const char *, int);
    int (*cb_process_metrics)(struct legacy_instance *, struct cmt *, struct cmt **,
                             const char *, int);
    int (*cb_process_traces)(struct legacy_instance *, struct ctrace *, struct ctrace **,
                            const char *, int);
    int (*cb_process_profiles)(struct legacy_instance *, struct cprof *, const char *, int);
    int (*cb_exit)(struct legacy_instance *, void *);
    int (*cb_notification)(struct legacy_instance *, struct flb_config *, void *);
    struct mk_list _head;
};

_Static_assert(sizeof(struct legacy_plugin) == offsetof(struct flb_processor_plugin, cb_preflight),
               "legacy descriptor offsets changed");
_Static_assert(sizeof(struct legacy_instance) == offsetof(struct flb_processor_instance, variant_properties),
               "legacy instance offsets changed");

struct options {
    char *marker;
};

static struct flb_config_map config_map[] = {
    {FLB_CONFIG_MAP_STR, "marker", "ok", 0, FLB_TRUE, offsetof(struct options, marker), "Probe"},
    {0}
};

static int init_legacy(struct legacy_instance *ins, void *source, int type, struct flb_config *config)
{
    struct options options = {0};

    (void) type;
    if (!source || ins->config != config || !ins->config_map || !ins->cmt ||
        !ins->log_decoder || !ins->log_encoder) {
        return -1;
    }
    if (flb_config_map_set(config, &ins->properties, ins->config_map, &options) != 0 ||
        !options.marker || strcmp(options.marker, "ok") != 0) {
        return -1;
    }
    ins->context = ins;
    fprintf(stderr, "legacy_dso_initialized\n");
    return 0;
}

static int process_legacy(struct legacy_instance *ins, void *data, const char *tag, int length)
{
    (void) data;
    (void) tag;
    (void) length;
    return ins->context == ins ? 0 : -1;
}

#if defined(PROBE_PREFLIGHT) || defined(PROBE_STOP) || defined(PROBE_UNFLAGGED)
static int init_current(struct flb_processor_instance *ins, void *source, int type,
                        struct flb_config *config)
{
    return init_legacy((struct legacy_instance *) ins, source, type, config);
}

static int process_current(struct flb_processor_instance *ins, void *data, const char *tag, int length)
{
    return process_legacy((struct legacy_instance *) ins, data, tag, length);
}

static int preflight_current(struct flb_processor_instance *ins, struct flb_config *config)
{
    struct options options = {0};

    if (ins->context || ins->cmt ||
        flb_config_map_set(config, &ins->properties, ins->config_map, &options) != 0) {
        return -1;
    }
    fprintf(stderr, "new_dso_preflight\n");
    return 0;
}

static int stop_current(struct flb_processor_instance *ins, void *data)
{
    if (data != ins || ins->context != ins) {
        return -1;
    }
    fprintf(stderr, "new_dso_input_stop\n");
    return 0;
}

#if defined(PROBE_STOP) || defined(PROBE_UNFLAGGED)
struct flb_processor_plugin processor_legacy_probe_plugin = {
    .flags = 0
#ifdef PROBE_STOP
        | FLB_PROCESSOR_FLAG_INPUT_STOP
#endif
#ifdef PROBE_PREFLIGHT
        | FLB_PROCESSOR_FLAG_PREFLIGHT
#endif
        ,
    .name = "legacy_probe",
    .description = "Extended descriptor probe",
    .config_map = config_map,
    .cb_init = init_current,
    .cb_process_logs = process_current,
    .cb_preflight = preflight_current,
    .cb_input_stop = stop_current
};
#else
/* Frozen intermediate ABI: the allocation really ends after cb_preflight. */
struct preflight_plugin {
    struct legacy_plugin base;
    int (*cb_preflight)(struct flb_processor_instance *, struct flb_config *);
};
_Static_assert(sizeof(struct preflight_plugin) == offsetof(struct flb_processor_plugin, cb_input_stop),
               "preflight-only descriptor offsets changed");
struct preflight_plugin processor_legacy_probe_plugin = {
    .base = {
        .flags = FLB_PROCESSOR_FLAG_PREFLIGHT,
        .name = "legacy_probe",
        .description = "Frozen preflight descriptor probe",
        .config_map = config_map,
        .cb_init = init_legacy,
        .cb_process_logs = process_legacy
    },
    .cb_preflight = preflight_current
};
#endif

#else
struct legacy_plugin processor_legacy_probe_plugin = {
    .name = "legacy_probe",
    .description = "Legacy descriptor probe",
    .config_map = config_map,
    .cb_init = init_legacy,
    .cb_process_logs = process_legacy
};
#endif

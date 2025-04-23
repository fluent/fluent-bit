#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mp.h>
#include <msgpack.h>

/* Context structure to hold processor configuration */
struct dedup_processor_ctx {
    flb_sds_t dedup_key;
};

/* Initialize deduplication processor context */
static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    const char *dedup_key;
    struct dedup_processor_ctx *ctx;

    /* Retrieve the deduplication key from the configuration */
    dedup_key = flb_processor_instance_get_property("dedup_key", ins);
    if (!dedup_key) {
        flb_plg_error(ins, "Missing 'dedup_key' property in configuration");
        return FLB_PROCESSOR_FAILURE;
    }

    /* Allocate context and store the deduplication key */
    ctx = flb_calloc(1, sizeof(struct dedup_processor_ctx));
    if (!ctx) {
        flb_errno();
        flb_plg_error(ins, "Unable to allocate memory for context");
        return FLB_PROCESSOR_FAILURE;
    }

    ctx->dedup_key = flb_sds_create(dedup_key);
    if (!ctx->dedup_key) {
        flb_errno();
        flb_free(ctx);
        flb_plg_error(ins, "Failed to allocate memory for dedup_key");
        return FLB_PROCESSOR_FAILURE;
    }

    /* Set context for later use */
    flb_processor_instance_set_context(ins, ctx);
    return FLB_PROCESSOR_SUCCESS;
}

/* Clean up processor context */
static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    struct dedup_processor_ctx *ctx = (struct dedup_processor_ctx *)data;

    if (ctx) {
        if (ctx->dedup_key) {
            flb_sds_destroy(ctx->dedup_key);
        }
        flb_free(ctx);
    }
    return FLB_PROCESSOR_SUCCESS;
}

/* Process a single record and return whether it should be deleted */
static int process_record(struct dedup_processor_ctx *ctx,
                         struct flb_mp_chunk_record *record,
                         struct flb_hash_table *hash_table)
{
    struct cfl_kvlist *kvlist;
    struct cfl_list *head;
    struct cfl_kvpair *kvpair;
    const char *value = NULL;
    size_t value_size = 0;
    void *hash_val;
    size_t hash_val_size;
    int ret;

    if (!record->cobj_record ||
        record->cobj_record->variant->type != CFL_VARIANT_KVLIST) {
        return FLB_FALSE;
    }

    kvlist = record->cobj_record->variant->data.as_kvlist;

    /* Find our dedup key and get its value */
    cfl_list_foreach(head, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (strncmp(kvpair->key, ctx->dedup_key, cfl_sds_len(ctx->dedup_key)) == 0 &&
            kvpair->val->type == CFL_VARIANT_STRING) {
            value = kvpair->val->data.as_string;
            value_size = cfl_variant_size_get(kvpair->val);
            break;
        }
    }

    if (!value) {
        return FLB_FALSE;
    }

    /* Check if value exists in hash table */
    ret = flb_hash_table_get(hash_table, value, value_size, &hash_val, &hash_val_size);
    if (ret > 0) {
        /* Duplicate found */
        return FLB_TRUE;
    }

    /* First time seeing this value, add to hash table */
    flb_hash_table_add(hash_table, value, value_size, "1", 1);
    return FLB_FALSE;
}

/* Process logs: remove duplicates based on a specified key */
static int cb_process_logs(struct flb_processor_instance *ins,
                          void *chunk_data,
                          const char *tag, int tag_len)
{
    struct flb_mp_chunk_cobj *chunk_cobj = (struct flb_mp_chunk_cobj *)chunk_data;
    struct dedup_processor_ctx *ctx = (struct dedup_processor_ctx *)ins->context;
    struct flb_mp_chunk_record *record;
    struct flb_hash_table *hash_table;
    int ret;
    size_t removed = 0;

    if (!ctx) {
        flb_plg_error(ins, "Context is not set");
        return FLB_PROCESSOR_FAILURE;
    }

    /* Initialize hash table to track unique values */
    hash_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 100, 0);
    if (!hash_table) {
        flb_plg_error(ins, "Failed to create hash table for deduplication");
        return FLB_PROCESSOR_FAILURE;
    }

    /* Iterate through each record in the chunk */
    while ((ret = flb_mp_chunk_cobj_record_next(chunk_cobj, &record)) == FLB_MP_CHUNK_RECORD_OK) {
        if (process_record(ctx, record, hash_table) == FLB_TRUE) {
            flb_mp_chunk_cobj_record_destroy(chunk_cobj, record);
            removed++;
        }
    }

    flb_plg_debug(ins, "Removed %zu duplicate records", removed);
    flb_hash_table_destroy(hash_table);
    return FLB_PROCESSOR_SUCCESS;
}


/* Plugin configuration map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "dedup_key", NULL,
     0, FLB_TRUE, offsetof(struct dedup_processor_ctx, dedup_key),
     "The key to check for duplicates"
    },
    {0}
};

/* Define the processor plugin */
struct flb_processor_plugin processor_chunk_dedup_plugin = {
    .name               = "chunk_dedup",
    .description        = "Deduplicate records by a specified key",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = NULL,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map        = config_map,
    .flags             = 0
};
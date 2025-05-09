#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mp.h>
#include <msgpack.h>

/* Maximum number of records to process in a single chunk */
#define CHUNK_DEDUP_MAX_RECORDS 1024


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
    int ret;
    struct dedup_processor_ctx *ctx;

    /* Allocate context and store the deduplication key */
    ctx = flb_calloc(1, sizeof(struct dedup_processor_ctx));
    if (!ctx) {
        flb_errno();
        flb_plg_error(ins, "Unable to allocate memory for context");
        return FLB_PROCESSOR_FAILURE;
    }

    /* Initialize the config map */
    ret = flb_processor_instance_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (ctx->dedup_key == NULL) {
        flb_plg_error(ins, "dedup_key is not set");
        flb_free(ctx);
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
        flb_free(ctx);
    }

    return FLB_PROCESSOR_SUCCESS;
}

/* Get the value of a key from a record */
static const char *get_key_value(struct dedup_processor_ctx *ctx,
                               struct flb_mp_chunk_record *record,
                               size_t *value_size)
{
    struct cfl_kvlist *kvlist;
    struct cfl_list *head;
    struct cfl_kvpair *kvpair;

    if (!record->cobj_record || 
        record->cobj_record->variant->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    kvlist = record->cobj_record->variant->data.as_kvlist;

    /* Find our dedup key and get its value */
    cfl_list_foreach(head, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);
        
        if (strncmp(kvpair->key, ctx->dedup_key, cfl_sds_len(ctx->dedup_key)) == 0 &&
            kvpair->val->type == CFL_VARIANT_STRING) {
            *value_size = cfl_variant_size_get(kvpair->val);
            return kvpair->val->data.as_string;
        }
    }

    return NULL;
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
    struct flb_mp_chunk_record *records[CHUNK_DEDUP_MAX_RECORDS];
    int should_remove[CHUNK_DEDUP_MAX_RECORDS] = {0}; /* 0 = keep, 1 = remove */
    int ret;
    int all_marked_for_removal = 1;
    size_t removed = 0;
    size_t record_count = 0;
    size_t i;
    const char *value;
    size_t value_size;
    void *out_buf;
    size_t out_size;

    if (!ctx) {
        flb_plg_error(ins, "Context is not set");
        return FLB_PROCESSOR_FAILURE;
    }

    /* Initialize hash table to track unique values */
    hash_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, CHUNK_DEDUP_MAX_RECORDS, 0);
    if (!hash_table) {
        flb_plg_error(ins, "Failed to create hash table for deduplication");
        return FLB_PROCESSOR_FAILURE;
    }

    /* Initialize tracking arrays */
    record_count = 0;
    
    /* First pass - collect records and mark duplicates for removal */
    while (record_count < CHUNK_DEDUP_MAX_RECORDS &&
           (ret = flb_mp_chunk_cobj_record_next(chunk_cobj, &record)) == FLB_MP_CHUNK_RECORD_OK) {
        
        records[record_count] = record;
        value = get_key_value(ctx, record, &value_size);
        
        if (value == NULL) {
            /* No matching key or not a string value, don't remove */
            should_remove[record_count] = 0;
        }
        else {
            /* Check if value is already in hash table */
            ret = flb_hash_table_get(hash_table, value, value_size, &out_buf, &out_size);
            if (ret >= 0) {
                /* Duplicate found, mark for removal */
                should_remove[record_count] = 1;
            }
            else {
                /* First occurrence, add to hash table and keep */
                flb_hash_table_add(hash_table, value, value_size, "1", 1);
                should_remove[record_count] = 0;
            }
        }
        
        record_count++;
    }

    /* If no records, nothing to do */
    if (record_count == 0) {
        flb_hash_table_destroy(hash_table);
        return FLB_PROCESSOR_SUCCESS;
    }

    /* Maybe not needed safety check: if all records would be removed, keep the first one */
    all_marked_for_removal = 1;
    for (i = 0; i < record_count; i++) {
        if (should_remove[i] == 0) {
            all_marked_for_removal = 0;
            break;
        }
    }

    if (all_marked_for_removal && record_count > 0) {
        should_remove[0] = 0; /* Keep the first record */
    }

    /* Second pass - remove the marked records */
    for (i = 0; i < record_count; i++) {
        if (should_remove[i]) {
            flb_mp_chunk_cobj_record_destroy(chunk_cobj, records[i]);
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

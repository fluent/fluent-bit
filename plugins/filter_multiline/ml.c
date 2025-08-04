/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "ml.h"
#include "ml_concat.h"

static struct ml_stream *get_by_id(struct ml_ctx *ctx, uint64_t stream_id);

/* Create an emitter input instance */
static int emitter_create(struct ml_ctx *ctx)
{
    int ret;
    struct flb_input_instance *ins;

    ret = flb_input_name_exists(ctx->emitter_name, ctx->config);
    if (ret == FLB_TRUE) {
        flb_plg_error(ctx->ins, "emitter_name '%s' already exists",
                      ctx->emitter_name);
        return -1;
    }

    ins = flb_input_new(ctx->config, "emitter", NULL, FLB_FALSE);
    if (!ins) {
        flb_plg_error(ctx->ins, "cannot create emitter instance");
        return -1;
    }

    /* Set the alias name */
    ret = flb_input_set_property(ins, "alias", ctx->emitter_name);
    if (ret == -1) {
        flb_plg_warn(ctx->ins,
                     "cannot set emitter_name, using fallback name '%s'",
                     ins->name);
    }

    /* Set the emitter_mem_buf_limit */
    if(ctx->emitter_mem_buf_limit > 0) {
        ins->mem_buf_limit = ctx->emitter_mem_buf_limit;
    }

    /* Set the storage type */
    ret = flb_input_set_property(ins, "storage.type",
                                 ctx->emitter_storage_type);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot set storage.type");
    }

    /* Initialize emitter plugin */
    ret = flb_input_instance_init(ins, ctx->config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot initialize emitter instance '%s'",
                      ins->name);
        flb_input_instance_exit(ins, ctx->config);
        flb_input_instance_destroy(ins);
        return -1;
    }

#ifdef FLB_HAVE_METRICS
    /* Override Metrics title */
    ret = flb_metrics_title(ctx->emitter_name, ins->metrics);
    if (ret == -1) {
        flb_plg_warn(ctx->ins, "cannot set metrics title, using fallback name %s",
                     ins->name);
    }
#endif

    /* Storage context */
    ret = flb_storage_input_create(ctx->config->cio, ins);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot initialize storage for stream '%s'",
                      ctx->emitter_name);
        flb_input_instance_exit(ins, ctx->config);
        flb_input_instance_destroy(ins);
        return -1;
    }
    ctx->ins_emitter = ins;
    return 0;
}

static int multiline_load_parsers(struct ml_ctx *ctx)
{
    int ret;
    struct mk_list *head;
    struct mk_list *head_p;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *val = NULL;
    struct flb_ml_parser_ins *parser_i;

    if (!ctx->multiline_parsers) {
        return -1;
    }

    /*
     * Iterate all 'multiline.parser' entries. Every entry is considered
     * a group which can have multiple multiline parser instances.
     */
    flb_config_map_foreach(head, mv, ctx->multiline_parsers) {
        mk_list_foreach(head_p, mv->val.list) {
            val = mk_list_entry(head_p, struct flb_slist_entry, _head);

            /* Create an instance of the defined parser */
            parser_i = flb_ml_parser_instance_create(ctx->m, val->str);
            if (!parser_i) {
                return -1;
            }

            /* Always override parent parser values */
            if (ctx->key_content) {
                ret = flb_ml_parser_instance_set(parser_i,
                                                 "key_content",
                                                 ctx->key_content);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "could not override 'key_content'");
                    return -1;
                }
            }
        }
    }

    return 0;
}

static int ingest_inline(struct ml_ctx *ctx,
                         flb_sds_t out_tag,
                         const void *buf, size_t buf_size)
{
    struct flb_input_instance *input_instance;
    struct flb_processor_unit *processor_unit;
    struct flb_processor      *processor;
    int                        result;
    if (ctx->ins->parent_processor != NULL) {
        processor_unit = (struct flb_processor_unit *) \
                            ctx->ins->parent_processor;
        processor = (struct flb_processor *) processor_unit->parent;
        input_instance = (struct flb_input_instance *) processor->data;

        if (processor->source_plugin_type == FLB_PLUGIN_INPUT) {
            result = flb_input_log_append_skip_processor_stages(
                        input_instance,
                        processor_unit->stage + 1,
                        out_tag, flb_sds_len(out_tag),
                        buf, buf_size);

            if (result == 0) {
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

static int flush_callback(struct flb_ml_parser *parser,
                          struct flb_ml_stream *mst,
                          void *data, char *buf_data, size_t buf_size)
{
    int ret;
    struct ml_ctx *ctx = data;
    struct ml_stream *stream;

    if (ctx->debug_flush) {
        flb_ml_flush_stdout(parser, mst, data, buf_data, buf_size);
    }

    if (ctx->use_buffer == FLB_FALSE) {
        /* Append incoming record to our msgpack context buffer */
        msgpack_sbuffer_write(&ctx->mp_sbuf, buf_data, buf_size);
        return 0;

    } else { /* buffered mode */
        stream = get_by_id(ctx, mst->id);
        if (!stream) {
            flb_plg_error(ctx->ins, "Could not find tag to re-emit from stream %s",
                        mst->name);
            return -1;
        }

        /* Emit record with original tag */
        flb_plg_trace(ctx->ins, "emitting from %s to %s", stream->input_name, stream->tag);
        ret = ingest_inline(ctx, stream->tag, buf_data, buf_size);
        if (!ret) {
            ret = in_emitter_add_record(stream->tag, flb_sds_len(stream->tag), buf_data, buf_size,
                                    ctx->ins_emitter, ctx->i_ins);
        }
        else {
            ret = 0;
        }

        return ret;
    }
}

static int cb_ml_init(struct flb_filter_instance *ins,
                      struct flb_config *config,
                      void *data)
{
    int ret;
    struct ml_ctx *ctx;
    flb_sds_t tmp;
    flb_sds_t emitter_name = NULL;
    int len;
    uint64_t stream_id;
    (void) config;

    ctx = flb_calloc(1, sizeof(struct ml_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->debug_flush = FLB_FALSE;
    ctx->config = config;
    ctx->timer_created = FLB_FALSE;

    /*
     * Config map is not yet set at this point in the code
     * user must explicitly set buffer to false to turn it off
     */
    ctx->use_buffer = FLB_TRUE;
    tmp = (char *) flb_filter_get_property("buffer", ins);
    if (tmp) {
        ctx->use_buffer = flb_utils_bool(tmp);
    }
    ctx->partial_mode = FLB_FALSE;
    tmp = (char *) flb_filter_get_property("mode", ins);
    if (tmp != NULL) {
        if (strcasecmp(tmp, FLB_MULTILINE_MODE_PARTIAL_MESSAGE) == 0) {
            ctx->partial_mode = FLB_TRUE;
        } else if (strcasecmp(tmp, FLB_MULTILINE_MODE_PARSER) == 0) {
            ctx->partial_mode = FLB_FALSE;
        } else {
            flb_plg_error(ins, "'Mode' must be '%s' or '%s'",
                          FLB_MULTILINE_MODE_PARTIAL_MESSAGE,
                          FLB_MULTILINE_MODE_PARSER);

            flb_free(ctx);

            return -1;
        }
    }

    if (ctx->partial_mode == FLB_TRUE && ctx->use_buffer == FLB_FALSE) {
        flb_plg_error(ins, "'%s' 'Mode' requires 'Buffer' to be 'On'",
                      FLB_MULTILINE_MODE_PARTIAL_MESSAGE);
    }

    if (ctx->use_buffer == FLB_FALSE) {
            /* Init buffers */
            msgpack_sbuffer_init(&ctx->mp_sbuf);
            msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);
    } else {
        /*
        * Emitter name: every buffered multiline instance needs an emitter input plugin,
        * with that one is able to emit records. We use a unique instance so we
        * can use the metrics interface.
        *
        * If not set, we define an emitter name
        *
        * Validate if the emitter_name has been set before to check with the
        * config map. If is not set, do a manual set of the property, so we let the
        * config map handle the memory allocation.
        */
        tmp = (char *) flb_filter_get_property("emitter_name", ins);
        if (!tmp) {
            emitter_name = flb_sds_create_size(64);
            if (!emitter_name) {
                flb_free(ctx);
                return -1;
            }

            tmp = flb_sds_printf(&emitter_name, "emitter_for_%s",
                                flb_filter_name(ins));
            if (!tmp) {
                flb_plg_error(ins, "cannot compose emitter_name");
                flb_sds_destroy(emitter_name);
                flb_free(ctx);
                return -1;
            }

            flb_filter_set_property(ins, "emitter_name", emitter_name);
            flb_plg_info(ins, "created emitter: %s", emitter_name);
            flb_sds_destroy(emitter_name);
        }
    }

    /* Load the config map */
    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set plugin context */
    flb_filter_set_context(ins, ctx);

    if (ctx->key_content == NULL && ctx->partial_mode == FLB_TRUE) {
        flb_plg_error(ins, "'Mode' '%s' requires 'multiline.key_content'",
                      FLB_MULTILINE_MODE_PARTIAL_MESSAGE);
        flb_free(ctx);
        return -1;
    }

    if (ctx->partial_mode == FLB_FALSE && mk_list_size(ctx->multiline_parsers) == 0) {
        flb_plg_error(ins, "The default 'Mode' '%s' requires at least one 'multiline.parser'",
                      FLB_MULTILINE_MODE_PARSER);
        flb_free(ctx);
        return -1;
    }


    if (ctx->use_buffer == FLB_TRUE) {
        /*
        * Emitter Storage Type: the emitter input plugin to be created by default
        * uses memory buffer, this option allows to define a filesystem mechanism
        * for new records created (only if the main service is also filesystem
        * enabled).
        *
        * On this code we just validate the input type: 'memory' or 'filesystem'.
        */
        tmp = ctx->emitter_storage_type;
        if (strcasecmp(tmp, "memory") != 0 && strcasecmp(tmp, "filesystem") != 0) {
            flb_plg_error(ins, "invalid 'emitter_storage.type' value. Only "
                        "'memory' or 'filesystem' types are allowed");
            flb_free(ctx);
            return -1;
        }

        /* Create the emitter context */
        ret = emitter_create(ctx);
        if (ret == -1) {
            flb_free(ctx);
            return -1;
        }

        /* Register a metric to count the number of emitted records */
#ifdef FLB_HAVE_METRICS
        ctx->cmt_emitted = cmt_counter_create(ins->cmt,
                                            "fluentbit", "filter", "emit_records_total",
                                            "Total number of emitted records",
                                            1, (char *[]) {"name"});

        /* OLD api */
        flb_metrics_add(FLB_MULTILINE_METRIC_EMITTED,
                        "emit_records", ctx->ins->metrics);
#endif
    }
        /* Register a metric to count the number of emitted records */
        /* Truncated metrics always should be existing. */
#ifdef FLB_HAVE_METRICS
        ctx->cmt_truncated = cmt_counter_create(ins->cmt,
                                                "fluentbit", "filter", "emit_truncated_total",
                                                "Total number of truncated occurence of multiline",
                                                1, (char *[]) {"name"});

        /* OLD api */
        flb_metrics_add(FLB_MULTILINE_METRIC_TRUNCATED,
                        "emit_truncated", ctx->ins->metrics);
#endif

    mk_list_init(&ctx->ml_streams);
    mk_list_init(&ctx->split_message_packers);

    if (ctx->partial_mode == FLB_FALSE) {
        /* Create multiline context */
        ctx->m = flb_ml_create(config, ctx->ins->name);
        if (!ctx->m) {
            /*
            * we don't free the context since upon init failure, the exit
            * callback will be triggered with our context set above.
            */
            return -1;
        }

        /* Load the parsers/config */
        ret = multiline_load_parsers(ctx);
        if (ret == -1) {
            return -1;
        }

        if (ctx->use_buffer == FLB_TRUE) {

            ctx->m->flush_ms = ctx->flush_ms;
            ret = flb_ml_auto_flush_init(ctx->m);
            if (ret == -1) {
                return -1;
            }
        } else {
            /* Create a stream for this file */
            len = strlen(ins->name);
            ret = flb_ml_stream_create(ctx->m,
                                    ins->name, len,
                                    flush_callback, ctx,
                                    &stream_id);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "could not create multiline stream");
                return -1;
            }
            ctx->stream_id = stream_id;
        }
    }

    return 0;
}

void ml_stream_destroy(struct ml_stream *stream)
{
    if (!stream) {
        return;
    }

    if (stream->input_name) {
        flb_sds_destroy(stream->input_name);
    }
    if (stream->tag) {
        flb_sds_destroy(stream->tag);
    }
    flb_free(stream);
    return;
}

static struct ml_stream *get_by_id(struct ml_ctx *ctx, uint64_t stream_id)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct ml_stream *stream;

    mk_list_foreach_safe(head, tmp, &ctx->ml_streams) {
        stream = mk_list_entry(head, struct ml_stream, _head);
        if (stream->stream_id == stream_id) {
            return stream;
        }
    }

    return NULL;
}

static struct ml_stream *get_or_create_stream(struct ml_ctx *ctx,
                                              struct flb_input_instance *i_ins,
                                              const char *tag, int tag_len)
{
    uint64_t stream_id;
    struct mk_list *tmp;
    struct mk_list *head;
    struct ml_stream *stream;
    flb_sds_t stream_name;
    flb_sds_t tmp_sds;
    int name_check;
    int tag_check;
    int len;
    int ret;

    mk_list_foreach_safe(head, tmp, &ctx->ml_streams) {
        stream = mk_list_entry(head, struct ml_stream, _head);
        name_check = strcmp(stream->input_name, i_ins->name);
        tag_check = strcmp(stream->tag, tag);
        if (tag_check == 0 && name_check == 0) {
            flb_plg_trace(ctx->ins, "using stream %s_%s", stream->input_name, stream->tag);
            return stream;
        }
    }

    /* create a new stream */
    stream_name = flb_sds_create_size(64);

    tmp_sds = flb_sds_printf(&stream_name, "%s_%s", i_ins->name, tag);
    if (!tmp_sds) {
        flb_errno();
        flb_sds_destroy(stream_name);
        return NULL;
    }
    stream_name = tmp_sds;

    stream = flb_calloc(1, sizeof(struct ml_stream));
    if (!stream) {
        flb_errno();
        flb_sds_destroy(stream_name);
        return NULL;
    }

    tmp_sds = flb_sds_create(tag);
    if (!tmp_sds) {
        flb_errno();
        flb_sds_destroy(stream_name);
        ml_stream_destroy(stream);
        return NULL;
    }
    stream->tag = tmp_sds;

    tmp_sds = flb_sds_create(i_ins->name);
    if (!tmp_sds) {
        flb_errno();
        flb_sds_destroy(stream_name);
        ml_stream_destroy(stream);
        return NULL;
    }
    stream->input_name = tmp_sds;

    /* Create an flb_ml_stream for this stream */
    flb_plg_info(ctx->ins, "created new multiline stream for %s", stream_name);
    len = flb_sds_len(stream_name);
    ret = flb_ml_stream_create(ctx->m,
                               stream_name, len,
                               flush_callback, ctx,
                               &stream_id);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not create multiline stream for %s",
                      stream_name);
        flb_sds_destroy(stream_name);
        ml_stream_destroy(stream);
        return NULL;
    }
    stream->stream_id = stream_id;
    mk_list_add(&stream->_head, &ctx->ml_streams);
    flb_plg_debug(ctx->ins, "Created new ML stream for %s", stream_name);
    flb_sds_destroy(stream_name);

    return stream;
}

static void partial_timer_cb(struct flb_config *config, void *data)
{
    struct ml_ctx *ctx = data;
    (void) config;
    struct mk_list *tmp;
    struct mk_list *head;
    struct split_message_packer *packer;
    unsigned long long now;
    unsigned long long diff;
    int ret;

    now = ml_current_timestamp();

    mk_list_foreach_safe(head, tmp, &ctx->split_message_packers) {
        packer = mk_list_entry(head, struct split_message_packer, _head);

        diff = now - packer->last_write_time;
        if (diff <= ctx->flush_ms) {
            continue;
        }

        mk_list_del(&packer->_head);
        ml_split_message_packer_complete(packer);
        /* re-emit record with original tag */
        if (packer->log_encoder.output_buffer != NULL &&
            packer->log_encoder.output_length > 0) {

            flb_plg_trace(ctx->ins, "emitting from %s to %s", packer->input_name, packer->tag);

            ret = ingest_inline(ctx, packer->tag, packer->log_encoder.output_buffer,
                            packer->log_encoder.output_length);
            if (!ret) {
                ret = in_emitter_add_record(packer->tag, flb_sds_len(packer->tag),
                                        packer->log_encoder.output_buffer,
                                        packer->log_encoder.output_length,
                                        ctx->ins_emitter,
                                        ctx->i_ins);
            }
            else {
                ret = 0;
            }
            if (ret < 0) {
                /* this shouldn't happen in normal execution */
                flb_plg_warn(ctx->ins,
                             "Couldn't send concatenated record of size %zu "
                             "bytes to in_emitter %s",
                             packer->log_encoder.output_length,
                             ctx->ins_emitter->name);
            }
        }
        ml_split_message_packer_destroy(packer);
    }
}

static int ml_filter_partial(const void *data, size_t bytes,
                             const char *tag, int tag_len,
                             void **out_buf, size_t *out_bytes,
                             struct flb_filter_instance *f_ins,
                             struct flb_input_instance *i_ins,
                             void *filter_context,
                             struct flb_config *config)
{
    int ret;
    struct ml_ctx *ctx = filter_context;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    int partial_records = 0;
    int return_records = 0;
    int partial = FLB_FALSE;
    int is_last_partial = FLB_FALSE;
    struct split_message_packer *packer;
    char *partial_id_str = NULL;
    size_t partial_id_size = 0;
    struct flb_sched *sched;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    (void) f_ins;
    (void) config;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    /*
     * create a timer that will run periodically and check if pending buffers
     * have expired
     * this is created once on the first flush
     */
    if (ctx->timer_created == FLB_FALSE) {
        flb_plg_debug(ctx->ins,
                      "Creating flush timer with frequency %dms",
                      ctx->flush_ms);

        sched = flb_sched_ctx_get();

        ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                        ctx->flush_ms / 2, partial_timer_cb,
                                        ctx, NULL);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to create flush timer");
        } else {
            ctx->timer_created = FLB_TRUE;
        }
    }

    /*
     * Create temporary msgpack buffer
     * for non-partial messages which are passed on as-is
     */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        partial = ml_is_partial(log_event.body);
        if (partial == FLB_TRUE) {
            partial_records++;
            ret = ml_get_partial_id(log_event.body, &partial_id_str, &partial_id_size);
            if (ret == -1) {
                flb_plg_warn(ctx->ins, "Could not find partial_id but partial_message key is FLB_TRUE for record with tag %s", tag);
                /* handle this record as non-partial */
                partial_records--;
                goto pack_non_partial;
            }
            packer = ml_get_packer(&ctx->split_message_packers, tag,
                                   i_ins->name, partial_id_str, partial_id_size);
            if (packer == NULL) {
                flb_plg_trace(ctx->ins, "Found new partial record with tag %s", tag);
                packer = ml_create_packer(tag, i_ins->name, partial_id_str, partial_id_size,
                                          log_event.body, ctx->key_content, &log_event.timestamp);
                if (packer == NULL) {
                    flb_plg_warn(ctx->ins, "Could not create packer for partial record with tag %s", tag);
                    /* handle this record as non-partial */
                    partial_records--;
                    goto pack_non_partial;
                }
                mk_list_add(&packer->_head, &ctx->split_message_packers);
            }
            ret = ml_split_message_packer_write(packer, log_event.body, ctx->key_content);
            if (ret < 0) {
                flb_plg_warn(ctx->ins, "Could not append content for partial record with tag %s", tag);
                /* handle this record as non-partial */
                partial_records--;
                goto pack_non_partial;
            }
            is_last_partial = ml_is_partial_last(log_event.body);
            if (is_last_partial == FLB_TRUE) {
                /* emit the record in this filter invocation */
                return_records++;
                ml_split_message_packer_complete(packer);
                ml_append_complete_record(packer, &log_encoder);
                mk_list_del(&packer->_head);
                ml_split_message_packer_destroy(packer);
            }
        } else {

pack_non_partial:
            return_records++;
            /* record passed from filter as-is */

            ret = flb_log_event_encoder_emit_raw_record(
                    &log_encoder,
                    log_decoder.record_base,
                    log_decoder.record_length);

            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_error(ctx->ins,
                              "Log event encoder initialization error : %d", ret);
            }
        }
    }

    if (partial_records == 0) {
        /* if no records were partial, we didn't modify the chunk */
        flb_log_event_decoder_destroy(&log_decoder);
        flb_log_event_encoder_destroy(&log_encoder);

        msgpack_sbuffer_destroy(&tmp_sbuf);

        return FLB_FILTER_NOTOUCH;
    } else if (return_records > 0) {
        /* some new records can be returned now, return a new buffer */
        if (log_encoder.output_length > 0) {
            *out_buf   = log_encoder.output_buffer;
            *out_bytes = log_encoder.output_length;

            ret = FLB_FILTER_MODIFIED;

            flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
        }
        else {
            ret = FLB_FILTER_NOTOUCH;
        }

        flb_log_event_decoder_destroy(&log_decoder);
        flb_log_event_encoder_destroy(&log_encoder);

        return ret;
    } else {
        /* no records to return right now, free buffer */
        flb_log_event_decoder_destroy(&log_decoder);
        flb_log_event_encoder_destroy(&log_encoder);

        msgpack_sbuffer_destroy(&tmp_sbuf);
    }

    return FLB_FILTER_MODIFIED;
}

static int cb_ml_filter(const void *data, size_t bytes,
                        const char *tag, int tag_len,
                        void **out_buf, size_t *out_bytes,
                        struct flb_filter_instance *f_ins,
                        struct flb_input_instance *i_ins,
                        void *filter_context,
                        struct flb_config *config)
{
    size_t                       tmp_size;
    char                        *tmp_buf;
    struct flb_log_event_decoder decoder;
    struct ml_stream            *stream;
    struct flb_log_event         event;
    int                          ret;
    struct ml_ctx               *ctx;
#ifdef FLB_HAVE_METRICS
    uint64_t ts;
    char *name;
#endif

    (void) f_ins;
    (void) config;

    ctx = (struct ml_ctx *) filter_context;

    if (i_ins == ctx->ins_emitter) {
        flb_plg_trace(ctx->ins, "not processing records from the emitter");
        return FLB_FILTER_NOTOUCH;
    }

    if (ctx->i_ins == NULL){
        ctx->i_ins = i_ins;
    }
    if (ctx->i_ins != i_ins) {
        flb_plg_trace(ctx->ins, "input instance changed from %s to %s",
                     ctx->i_ins->name, i_ins->name);
        ctx->i_ins = i_ins;
    }

    /* 'partial_message' mode */
    if (ctx->partial_mode == FLB_TRUE) {
        return ml_filter_partial(data, bytes, tag, tag_len,
                                 out_buf, out_bytes,
                                 f_ins, i_ins,
                                 filter_context, config);
    }

    /* 'parser' mode */
    if (ctx->use_buffer == FLB_FALSE) {
        /* reset mspgack size content */
        ctx->mp_sbuf.size = 0;

        /* process records */
        flb_log_event_decoder_init(&decoder, (char *) data, bytes);

        while (flb_log_event_decoder_next(&decoder, &event) ==
               FLB_EVENT_DECODER_SUCCESS) {
            ret = flb_ml_append_event(ctx->m, ctx->stream_id, &event);

            if (ret == FLB_MULTILINE_TRUNCATED) {
                flb_plg_warn(ctx->ins,
                             "multiline message truncated due to buffer limit");
#ifdef FLB_HAVE_METRICS
                name = (char *) flb_filter_name(ctx->ins);
                ts = cfl_time_now();
                cmt_counter_inc(ctx->cmt_truncated, ts, 1, (char *[]) {name});

                /* old api */
                flb_metrics_sum(FLB_MULTILINE_METRIC_TRUNCATED, 1, ctx->ins->metrics);
#endif
            }
            else if (ret != FLB_MULTILINE_OK) {
                flb_plg_debug(ctx->ins,
                              "could not append object from tag: %s", tag);
            }
        }

        flb_log_event_decoder_destroy(&decoder);

        /* flush all pending data (there is no auto-flush when unbuffered) */
        flb_ml_flush_pending_now(ctx->m);

        if (ctx->mp_sbuf.size > 0) {
            /*
            * If the filter will report a new set of records because the
            * original data was modified, we make a copy to a new memory
            * area, since the buffer might be invalidated in the filter
            * chain.
            */

            tmp_buf = flb_malloc(ctx->mp_sbuf.size);
            if (!tmp_buf) {
                flb_errno();
                return FLB_FILTER_NOTOUCH;
            }
            tmp_size = ctx->mp_sbuf.size;
            memcpy(tmp_buf, ctx->mp_sbuf.data, tmp_size);
            *out_buf = tmp_buf;
            *out_bytes = tmp_size;
            ctx->mp_sbuf.size = 0;

            return FLB_FILTER_MODIFIED;
        }

        /* unlikely to happen.. but just in case */
        return FLB_FILTER_NOTOUCH;

    } else { /* buffered mode */
        stream = get_or_create_stream(ctx, i_ins, tag, tag_len);

        if (!stream) {
            flb_plg_error(ctx->ins, "Could not find or create ML stream for %s", tag);
            return FLB_FILTER_NOTOUCH;
        }

        /* process records */
        flb_log_event_decoder_init(&decoder, (char *) data, bytes);

        while (flb_log_event_decoder_next(&decoder, &event) ==
               FLB_EVENT_DECODER_SUCCESS) {
            ret = flb_ml_append_event(ctx->m, stream->stream_id, &event);

            if (ret == FLB_MULTILINE_TRUNCATED) {
                flb_plg_warn(ctx->ins,
                             "multiline message truncated due to buffer limit");
#ifdef FLB_HAVE_METRICS
                name = (char *) flb_filter_name(ctx->ins);
                ts = cfl_time_now();
                cmt_counter_inc(ctx->cmt_truncated, ts, 1, (char *[]) {name});

                /* old api */
                flb_metrics_sum(FLB_MULTILINE_METRIC_TRUNCATED, 1, ctx->ins->metrics);
#endif
            }
            else if (ret != FLB_MULTILINE_OK) {
                flb_plg_debug(ctx->ins,
                              "could not append object from tag: %s", tag);
            }
            else if (ret == FLB_MULTILINE_OK) {
#ifdef FLB_HAVE_METRICS
                name = (char *) flb_filter_name(ctx->ins);
                ts = cfl_time_now();
                cmt_counter_inc(ctx->cmt_emitted, ts, 1, (char *[]) {name});

                /* old api */
                flb_metrics_sum(FLB_MULTILINE_METRIC_EMITTED, 1, ctx->ins->metrics);
#endif
            }
        }

        flb_log_event_decoder_destroy(&decoder);

        /*
         * always returned modified, which will be 0 records, since the emitter takes
         * all records.
        */
        return FLB_FILTER_MODIFIED;
    }
}

static int cb_ml_exit(void *data, struct flb_config *config)
{
    struct ml_ctx *ctx = data;
    struct mk_list *tmp;
    struct mk_list *head;
    struct ml_stream *stream;

    if (!ctx) {
        return 0;
    }

    if (ctx->m) {
        flb_ml_destroy(ctx->m);
    }

    mk_list_foreach_safe(head, tmp, &ctx->ml_streams) {
        stream = mk_list_entry(head, struct ml_stream, _head);
        mk_list_del(&stream->_head);
        ml_stream_destroy(stream);
    }

    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    flb_free(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "debug_flush", "false",
     0, FLB_TRUE, offsetof(struct ml_ctx, debug_flush),
     "enable debugging for concatenation flush to stdout"
    },

    {
     FLB_CONFIG_MAP_BOOL, "buffer", "true",
     0, FLB_TRUE, offsetof(struct ml_ctx, use_buffer),
     "Enable buffered mode. In buffered mode, the filter can concatenate "
     "multilines from inputs that ingest records one by one (ex: Forward), "
     "rather than in chunks, re-emitting them into the beggining of the "
     "pipeline using the in_emitter instance. "
     "With buffer off, this filter will not work with most inputs, except tail."
    },

    {
     FLB_CONFIG_MAP_STR, "mode", "parser",
     0, FLB_TRUE, offsetof(struct ml_ctx, mode),
     "Mode can be 'parser' for regex concat, or 'partial_message' to "
     "concat split docker logs."
    },

    {
     FLB_CONFIG_MAP_INT, "flush_ms", "2000",
     0, FLB_TRUE, offsetof(struct ml_ctx, flush_ms),
     "Flush time for pending multiline records"
    },

    /* Multiline Core Engine based API */
    {
     FLB_CONFIG_MAP_CLIST, "multiline.parser", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct ml_ctx, multiline_parsers),
     "specify one or multiple multiline parsers: docker, cri, go, java, etc."
    },

    {
     FLB_CONFIG_MAP_STR, "multiline.key_content", NULL,
     0, FLB_TRUE, offsetof(struct ml_ctx, key_content),
     "specify the key name that holds the content to process."
    },

    /* emitter config */
    {
     FLB_CONFIG_MAP_STR, "emitter_name", NULL,
     FLB_FALSE, FLB_TRUE, offsetof(struct ml_ctx, emitter_name),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "emitter_storage.type", "memory",
     FLB_FALSE, FLB_TRUE, offsetof(struct ml_ctx, emitter_storage_type),
     NULL
    },
    {
     FLB_CONFIG_MAP_SIZE, "emitter_mem_buf_limit", FLB_MULTILINE_MEM_BUF_LIMIT_DEFAULT,
     FLB_FALSE, FLB_TRUE, offsetof(struct ml_ctx, emitter_mem_buf_limit),
     "set a memory buffer limit to restrict memory usage of emitter"
    },

    /* EOF */
    {0}
};

struct flb_filter_plugin filter_multiline_plugin = {
    .name         = "multiline",
    .description  = "Concatenate multiline messages",
    .cb_init      = cb_ml_init,
    .cb_filter    = cb_ml_filter,
    .cb_exit      = cb_ml_exit,
    .config_map   = config_map,
    .flags        = 0
};

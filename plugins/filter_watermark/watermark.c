/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>
#include "stdlib.h"

#include "watermark.h"
#include "heap.h"

#include <stdio.h>
#include <sys/types.h>


static int configure(struct flb_filter_watermark_ctx *ctx, struct flb_filter_instance *f_ins)
{
    const char *str = NULL;
    double val  = 0;
    char *endp;

    ctx->win_right_edge = 0;;
    ctx->win_left_edge = 0;
    ctx->init_flag = 0; 

    /* window size */
    str = flb_filter_get_property("window_size", f_ins);

    if (str != NULL && (val = strtod(str, &endp)) > 1) {
        ctx->window_size = val;
    } else {
        ctx->window_size = WINDOW_SIZE_DEFAULT_VALUE;
    }
    
    /* watermark */
    str = flb_filter_get_property("watermark", f_ins);

    if (str != NULL && (val = strtod(str, &endp)) > 1) {
        ctx->watermark = val;
    } else {
        ctx->watermark = WATERMARK_DEFAULT_VALUE;
    }

    /*time_field*/ 
    str = flb_filter_get_property("time_field", f_ins);
    if (!str) {
        flb_plg_error(ctx->ins,  "time_field is not defined!");
        return -1;
    }
    ctx->time_field = flb_sds_create(str);

    return 0;
}

int deconstructor_imp(void *v) 
{
    struct flb_filter_watermark_record *r = v;
    msgpack_sbuffer_free(r->sbuffer);
    free(r);
    return 0; 
}

int compare_imp(void *v0, void *v1) 
{
    struct flb_filter_watermark_record *r0 = v0;
    struct flb_filter_watermark_record *r1 = v1;

    struct tm *t0 = &(r0->time_stamp);
    struct tm *t1 = &(r1->time_stamp);
    time_t timer0 = mktime(t0);
    time_t timer1 = mktime(t1);

    if (timer0 < timer1)
        return -1;
    else if (timer0 > timer1)
        return 1;
    else
        return 0;
}

static int ingest_data(struct flb_filter_watermark_ctx *context, void *ptr) 
{
    struct flb_filter_watermark_record *record_ptr = ptr;  

    struct tm *t = &(record_ptr->time_stamp);
    time_t tl = mktime(t);
    const char *fmt = "%a, %d %b %Y %T %z";
    char outstr[200] = {0};

    struct c_heap_t *h = context->h;
    time_t win_right_edge = context->win_right_edge;
    time_t win_left_edge  = context->win_left_edge;
    int watermark = context->watermark;
    int window_size = context->window_size;

    struct flb_filter_watermark_record *tmp_record;
    struct tm *tmp_record_timestamp;
  
    int ret = 0;
  
    if (context->init_flag == 0) {
        context->init_flag = 1;
        context->win_right_edge = tl + window_size;
        context->win_left_edge  = tl;
        c_heap_insert(h, record_ptr);
        return ret; 
    }

    if (tl < win_left_edge) {
        /* Drop the data. */
        strftime(outstr, sizeof(outstr), fmt, t);
        flb_plg_warn(context->ins,  "Record with timestamp %s arrives too late, Drop It!", outstr);
        ret = -1;
        return ret;
     } else {
        /* Ingest the data. */
        c_heap_insert(h, record_ptr);
     }

     /* main loop to flush out data */
     while(tl - watermark >= win_right_edge) {
         /*Dump all data into array to flush out*/
         tmp_record = c_heap_read_root(h);
         if (tmp_record == NULL) {
             /* This place could not be reached, since at least one piece of record is in the heap*/
             flb_plg_error(context->ins,  "Fatal Error!");
             ret = -1;
             break;
         }
         tmp_record_timestamp = &(tmp_record->time_stamp);
         strftime(outstr, sizeof(outstr), fmt, tmp_record_timestamp);
         flb_plg_debug(context->ins, "%s        %ld\n", outstr, mktime(tmp_record_timestamp));

         /* Make a copy of ptr of record and pop the heap top*/
         if (mktime(tmp_record_timestamp) <= win_right_edge) { 
             if (context->record_count >= CACHE_SIZE_DEFAULT_VALUE) {
                 flb_plg_info(context->ins, "Cache is full and drop the record to flush out\n");
             } else {
                 context->record_pointer_cache_out_array[context->record_count] = tmp_record;
                 ++(context->record_count);
             }
             c_heap_get_root(h);
             ret = 1;
             continue;
         } else {
             /* It means that current top of head is in another windows. */
             /* Update the left and right edge with new timestamp. */
             win_left_edge = mktime(tmp_record_timestamp);
             win_right_edge = win_left_edge + window_size; 
             break;
         }
    }
  
    /* Update context. */
    context->win_right_edge = win_right_edge;
    context->win_left_edge = win_left_edge;
    return ret;
}


static int cb_watermark_init(struct flb_filter_instance *f_ins,
                             struct flb_config *config,
                             void *data)
{
    int ret;
    struct flb_filter_watermark_ctx *ctx;

    /* Create context */
    ctx = flb_malloc(sizeof(struct flb_filter_watermark_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = f_ins;

    /* parse plugin configuration  */
    ret = configure(ctx, f_ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set our context */
    flb_filter_set_context(f_ins, ctx);
    ctx->h = c_heap_create(compare_imp, deconstructor_imp);
    ctx->record_count = 0; 
    
    return 0;
}

static int cb_watermark_filter(const void *data, size_t bytes,
                               const char *tag, int tag_len,
                               void **out_buf, size_t *out_size,
                               struct flb_filter_instance *f_ins,
                               void *context,
                               struct flb_config *config)
{
    msgpack_object root;
    msgpack_object map;
    msgpack_object key;
    msgpack_object value;
    int i; 
    int map_size; 
    int ret;
    struct tm tm0;

    msgpack_unpacked result;
    msgpack_unpacked * destroy_result;
    size_t off = 0;

    char tmp_buf[45];
    int tmp_buf_len = 45;

    struct flb_filter_watermark_ctx *ctx = context; 
    destroy_result = &result;

    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_sbuffer *tmp_sbuf;
    tmp_sbuf = msgpack_sbuffer_new();
    msgpack_sbuffer_init(tmp_sbuf);
    
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        for (i = 0; i < map_size; i++) {
            key = map.via.map.ptr[i].key;

            if (flb_sds_cmp(ctx->time_field, (char *) key.via.str.ptr, key.via.str.size) != 0) {
                /* ignore the key if the key is not the same as time_filed. */
                continue;
            }

            value = map.via.map.ptr[i].val;
            if (value.type == MSGPACK_OBJECT_STR) {
                flb_plg_debug(ctx->ins, "size is %d", value.via.str.size);
                flb_plg_debug(ctx->ins, "content is %s", value.via.str.ptr);
 		
                if (value.via.str.size > tmp_buf_len) {
                    flb_plg_info(ctx->ins, "Timestamp string length is too long to be correct, drop the record\n");
                    continue;
                }                

                flb_sds_t buf;
                buf = flb_sds_create_len(value.via.str.ptr, value.via.str.size);
                memset(tmp_buf, 0, tmp_buf_len);
                strcpy(tmp_buf, buf);
                flb_sds_destroy(buf);
            }

            /* we reply on strptime to check the format. */
            memset(&tm0, 0, sizeof(struct tm));
            /* strptime("2021-11-12 18:31:01", "%Y-%m-%d %H:%M:%S", &tm0); */
            if (strptime(tmp_buf, "%Y-%m-%d %H:%M:%S", &tm0) == 0) {
                flb_plg_info(ctx->ins, "Timestamp format is not acceptable by strptime, drop the record\n");
                continue;
            }

            /* when it reaches here, we need to malloc memory to store all the content of record and insert record into heap. */
	    struct flb_filter_watermark_record *tmp_ptr = flb_malloc(sizeof(struct flb_filter_watermark_record));        
            msgpack_sbuffer_write(tmp_sbuf, data, bytes);
	    tmp_ptr->time_stamp = tm0;
            tmp_ptr->sbuffer = tmp_sbuf;
            tmp_ptr->bytes = bytes;

            ret = ingest_data(ctx, tmp_ptr);
	    if (ret == 1) {
                msgpack_object root_tmp;
                msgpack_unpacked result_tmp;
                size_t off_tmp = 0;
                size_t bytes = 0;
                for (i=0; i < ctx->record_count; i++) {
                    /* re-use tmp_ptr variable*/ 
                    tmp_ptr = ctx->record_pointer_cache_out_array[i];
                    tmp_sbuf = tmp_ptr->sbuffer;
		    bytes = tmp_ptr->bytes;
               	    msgpack_unpacked_init(&result_tmp);
               	    while (msgpack_unpack_next(&result_tmp, tmp_sbuf->data, bytes, &off_tmp) == MSGPACK_UNPACK_SUCCESS) {
                        root_tmp = result_tmp.data;
                        msgpack_pack_object(&mp_pck, root_tmp);
		    }
		    off_tmp = 0;
	            msgpack_unpacked_destroy(&result_tmp);
                    msgpack_sbuffer_free(tmp_sbuf);
                    flb_free(tmp_ptr);
                }
                ctx->record_count = 0;
	    } else if (ret == -1) {
		/* record is too late or some other fatal error, we just clean up memory*/
                msgpack_sbuffer_free(tmp_sbuf);
                flb_free(tmp_ptr);
            } else {
                flb_plg_debug(ctx->ins, "No record pop up in this round");
                //return FLB_FILTER_MODIFIED;
            }
        }
    }

    /* There is no NONTOUCH branch, since we would cache every single piece of record here. */
    msgpack_unpacked_destroy(destroy_result);

    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_watermark_exit(void *data, struct flb_config *config)
{
    struct flb_filter_watermark_ctx *ctx = data;
    struct flb_filter_watermark_record *tmp_ptr;
    msgpack_sbuffer *tmp_sbuf;
    int i;
    for (i=0; i < ctx->record_count; i++) {
        tmp_ptr = ctx->record_pointer_cache_out_array[i];
        tmp_sbuf = tmp_ptr->sbuffer;
        msgpack_sbuffer_free(tmp_sbuf);
        flb_free(tmp_ptr);
    }
    ctx->record_count = 0;
    
    flb_sds_destroy(ctx->time_field);
    c_heap_destroy(ctx->h);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "watermark", NULL,
        0, FLB_FALSE, 0,
        "Watermark value."
    },
    {
        FLB_CONFIG_MAP_STR, "window_size", NULL,
        0, FLB_FALSE, 0,
        "Window size"
    },
    {
        FLB_CONFIG_MAP_STR, "time_field", NULL,
        0, FLB_FALSE, 0,
        "Time field name to use for inference."
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_watermark_plugin = {
    .name         = "watermark",
    .description  = "watermark algorithm to sort records in order",
    .cb_init      = cb_watermark_init,
    .cb_filter    = cb_watermark_filter,
    .cb_exit      = cb_watermark_exit,
    .config_map   = config_map,
    .flags        = 0
};
